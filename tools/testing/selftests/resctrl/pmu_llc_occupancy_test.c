// SPDX-License-Identifier: GPL-2.0
/*
 * Resctrl PMU LLC Occupancy test
 *
 * Test program to verify the resctrl PMU LLC occupancy measurement matches
 * the resctrl filesystem measurement.
 */

#include "resctrl.h"
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>

#define RESCTRL_PMU_NAME "resctrl"
#define ARRAY_SIZE_MB 1
#define PERM_ARRAY_SIZE (ARRAY_SIZE_MB * MB / sizeof(uint32_t))
#define MIN_EXPECTED_OCCUPANCY (800 * 1024)  // 800 KB
#define MAX_EXPECTED_OCCUPANCY (2.5 * MB)    // 2.5 MB
#define TOLERANCE_PERCENT 10
#define ITERATIONS_PER_CHECK 1000
#define CHILD_RUNTIME_MS 550
#define PARENT_WAIT_MS 500

static int find_pmu_type(const char *pmu_name)
{
	char path[256];
	FILE *file;
	int type;

	snprintf(path, sizeof(path), "/sys/bus/event_source/devices/%s/type", pmu_name);
	
	file = fopen(path, "r");
	if (!file) {
		ksft_print_msg("Failed to open %s: %s\n", path, strerror(errno));
		return -1;
	}
	
	if (fscanf(file, "%d", &type) != 1) {
		ksft_print_msg("Failed to read PMU type from %s\n", path);
		fclose(file);
		return -1;
	}
	
	fclose(file);
	return type;
}

/*
 * Create a random single-cycle permutation using the algorithm from:
 * https://crypto.stackexchange.com/a/51806
 * 
 * Algorithm:
 * 1. Create a set P of numbers 2..N
 * 2. Set Idx=1
 * 3. Draw a random member M from P, assign it to index Idx
 * 4. Remove the member from P
 * 5. Set Idx=M
 * 6. If P is nonempty repeat from step 3
 * 7. Assign 1 to the last spot at Idx
 */
static void create_single_cycle_permutation(uint32_t *perm, size_t n)
{
	uint32_t *pool;
	size_t pool_size;
	size_t idx;
	size_t i;

	/* Allocate pool for remaining elements */
	pool = malloc((n - 1) * sizeof(uint32_t));
	if (!pool) {
		perror("malloc");
		exit(1);
	}

	/* Initialize pool with values 2..n */
	for (i = 0; i < n - 1; i++) {
		pool[i] = i + 2;
	}
	pool_size = n - 1;

	/* Start at index 1 (0-indexed, so position 0) */
	idx = 0;

	/* Build the permutation */
	while (pool_size > 0) {
		/* Draw random member from pool */
		size_t rand_idx = rand() % pool_size;
		uint32_t m = pool[rand_idx];
		
		/* Assign it to current index */
		perm[idx] = m - 1;  /* Convert to 0-indexed */
		
		/* Remove from pool by copying last element to this position */
		pool[rand_idx] = pool[pool_size - 1];
		pool_size--;
		
		/* Next index is the value we just picked */
		idx = m - 1;  /* Convert to 0-indexed */
	}
	
	/* Assign 1 (0 in 0-indexed) to the last spot */
	perm[idx] = 0;
	
	free(pool);
}

/* Child process: Walk the permutation continuously */
static void child_walk_permutation(const char *group_name, size_t n, int ready_fd)
{
	uint32_t *perm;
	struct timespec start, now;
	size_t idx;
	size_t iterations = 0;
	uint8_t ready = 1;

	/* Add ourselves to the monitoring group BEFORE allocating memory */
	if (add_pid_to_monitoring_group(group_name, getpid()) < 0) {
		exit(1);
	}

	/* Now allocate and create the permutation - this will be tracked by resctrl */
	perm = malloc(n * sizeof(uint32_t));
	if (!perm) {
		perror("malloc");
		exit(1);
	}
	
	/* Create the permutation directly in the child */
	create_single_cycle_permutation(perm, n);

	/* Signal parent that we're ready */
	if (write(ready_fd, &ready, 1) != 1) {
		perror("write ready signal");
		exit(1);
	}
	close(ready_fd);

	/* Get start time */
	clock_gettime(CLOCK_MONOTONIC, &start);

	/* Walk the permutation continuously */
	idx = 0;
	while (1) {
		idx = perm[idx];
		iterations++;

		/* Check time every ITERATIONS_PER_CHECK iterations */
		if (iterations % ITERATIONS_PER_CHECK == 0) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
					  (now.tv_nsec - start.tv_nsec) / 1000000;
			
			if (elapsed_ms >= CHILD_RUNTIME_MS) {
				break;
			}
		}
	}

	free(perm);
	exit(0);
}

static int create_monitoring_group(const char *group_name)
{
	char path[512];
	int ret;

	snprintf(path, sizeof(path), "%s/mon_groups/%s", RESCTRL_PATH, group_name);
	
	ret = mkdir(path, 0755);
	if (ret < 0 && errno != EEXIST) {
		ksft_print_msg("Failed to create monitoring group %s: %s\n",
			       group_name, strerror(errno));
		return -1;
	}
	
	return 0;
}

static int add_pid_to_monitoring_group(const char *group_name, pid_t pid)
{
	char path[512];
	FILE *file;

	snprintf(path, sizeof(path), "%s/mon_groups/%s/tasks", RESCTRL_PATH, group_name);
	
	file = fopen(path, "w");
	if (!file) {
		ksft_print_msg("Failed to open %s: %s\n", path, strerror(errno));
		return -1;
	}
	
	if (fprintf(file, "%d\n", pid) < 0) {
		ksft_print_msg("Failed to write PID %d to %s\n", pid, path);
		fclose(file);
		return -1;
	}
	
	fclose(file);
	return 0;
}

static int read_llc_occupancy_from_resctrl(const char *group_name, unsigned long *occupancy)
{
	char path[512];
	FILE *file;
	char *line = NULL;
	size_t len = 0;
	int ret = -1;

	/* Try different domain IDs until we find one that exists */
	for (int domain = 0; domain < 4; domain++) {
		snprintf(path, sizeof(path), "%s/mon_groups/%s/mon_data/mon_L3_%02d/llc_occupancy",
			 RESCTRL_PATH, group_name, domain);
		
		file = fopen(path, "r");
		if (file) {
			if (getline(&line, &len, file) > 0) {
				*occupancy = strtoul(line, NULL, 10);
				ret = 0;
			}
			fclose(file);
			free(line);
			if (ret == 0)
				break;
		}
	}
	
	if (ret < 0) {
		ksft_print_msg("Failed to read LLC occupancy from resctrl\n");
	}
	
	return ret;
}

static int read_llc_occupancy_from_pmu(int pmu_type, const char *group_name, 
					unsigned long *occupancy)
{
	struct perf_event_attr pe = {0};
	char path[512];
	int mon_fd, perf_fd;
	int ret = -1;

	/* Open the monitoring file to get a file descriptor */
	for (int domain = 0; domain < 4; domain++) {
		snprintf(path, sizeof(path), "%s/mon_groups/%s/mon_data/mon_L3_%02d/llc_occupancy",
			 RESCTRL_PATH, group_name, domain);
		
		mon_fd = open(path, O_RDONLY);
		if (mon_fd >= 0)
			break;
	}
	
	if (mon_fd < 0) {
		ksft_print_msg("Failed to open monitoring file for PMU\n");
		return -1;
	}

	/* Setup perf event attributes */
	pe.type = pmu_type;
	pe.config = mon_fd;  /* Pass the file descriptor as config */
	pe.size = sizeof(pe);
	pe.disabled = 0;     /* Start enabled */
	pe.exclude_kernel = 0;
	pe.exclude_hv = 0;

	/* Open the perf event */
	perf_fd = perf_event_open(&pe, -1, 0, -1, 0);
	if (perf_fd < 0) {
		ksft_print_msg("Failed to open perf event: %s\n", strerror(errno));
		close(mon_fd);
		return -1;
	}

	/* Read the counter value */
	uint64_t value;
	
	if (read(perf_fd, &value, sizeof(value)) == sizeof(value)) {
		*occupancy = value;
		ret = 0;
	} else {
		ksft_print_msg("Failed to read PMU counter\n");
	}

	close(perf_fd);
	close(mon_fd);
	
	return ret;
}

static int remove_monitoring_group(const char *group_name)
{
	char path[512];
	
	snprintf(path, sizeof(path), "%s/mon_groups/%s", RESCTRL_PATH, group_name);
	return rmdir(path);
}

static bool pmu_llc_occupancy_feature_check(const struct resctrl_test *test)
{
	return resctrl_mon_feature_exists("L3_MON", "llc_occupancy");
}

static int pmu_llc_occupancy_run_test(const struct resctrl_test *test, 
				       const struct user_params *uparams)
{
	const char *group_name = "pmu_llc_test";
	unsigned long resctrl_occupancy, pmu_occupancy;
	int pmu_type;
	pid_t child_pid;
	int pipe_fds[2];
	int ret = -1;
	uint8_t ready;
	struct timespec ts;

	ksft_print_msg("Testing PMU LLC occupancy measurement\n");

	/* Find the resctrl PMU type */
	pmu_type = find_pmu_type(RESCTRL_PMU_NAME);
	if (pmu_type < 0) {
		ksft_print_msg("Resctrl PMU not found\n");
		return -1;
	}

	/* Create monitoring group */
	if (create_monitoring_group(group_name) < 0) {
		return -1;
	}

	/* Initialize random seed */
	srand(time(NULL));

	/* Create pipe for child ready signal */
	if (pipe(pipe_fds) < 0) {
		perror("pipe");
		goto cleanup_group;
	}

	/* Fork child process */
	child_pid = fork();
	if (child_pid < 0) {
		perror("fork");
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		goto cleanup_group;
	}

	if (child_pid == 0) {
		/* Child process */
		close(pipe_fds[0]);
		child_walk_permutation(group_name, PERM_ARRAY_SIZE, pipe_fds[1]);
		/* Should not reach here */
		exit(1);
	}

	/* Parent process */
	close(pipe_fds[1]);

	/* Wait for child to be ready (it will add itself to the monitoring group first) */
	if (read(pipe_fds[0], &ready, 1) != 1) {
		ksft_print_msg("Failed to get ready signal from child\n");
		close(pipe_fds[0]);
		kill(child_pid, SIGKILL);
		waitpid(child_pid, NULL, 0);
		goto cleanup_group;
	}
	close(pipe_fds[0]);

	ksft_print_msg("Child process (PID %d) ready and added to monitoring group %s\n", 
		       child_pid, group_name);

	/* Wait 500ms for cache to be populated */
	ts.tv_sec = 0;
	ts.tv_nsec = PARENT_WAIT_MS * 1000000;
	nanosleep(&ts, NULL);

	/* Read LLC occupancy from resctrl filesystem */
	if (read_llc_occupancy_from_resctrl(group_name, &resctrl_occupancy) < 0) {
		kill(child_pid, SIGKILL);
		waitpid(child_pid, NULL, 0);
		goto cleanup_group;
	}

	/* Read LLC occupancy from PMU */
	if (read_llc_occupancy_from_pmu(pmu_type, group_name, &pmu_occupancy) < 0) {
		kill(child_pid, SIGKILL);
		waitpid(child_pid, NULL, 0);
		goto cleanup_group;
	}

	/* Wait for child to complete */
	waitpid(child_pid, NULL, 0);

	/* Print results */
	ksft_print_msg("LLC Occupancy Results:\n");
	ksft_print_msg("  Resctrl FS: %lu bytes\n", resctrl_occupancy);
	ksft_print_msg("  PMU:        %lu bytes\n", pmu_occupancy);

	/* Check if values are within expected range */
	if (resctrl_occupancy < MIN_EXPECTED_OCCUPANCY || 
	    resctrl_occupancy > MAX_EXPECTED_OCCUPANCY) {
		ksft_print_msg("FAIL: Resctrl occupancy %lu outside expected range [%d, %.0f]\n",
			       resctrl_occupancy, MIN_EXPECTED_OCCUPANCY, MAX_EXPECTED_OCCUPANCY);
		goto cleanup_group;
	}

	if (pmu_occupancy < MIN_EXPECTED_OCCUPANCY || 
	    pmu_occupancy > MAX_EXPECTED_OCCUPANCY) {
		ksft_print_msg("FAIL: PMU occupancy %lu outside expected range [%d, %.0f]\n",
			       pmu_occupancy, MIN_EXPECTED_OCCUPANCY, MAX_EXPECTED_OCCUPANCY);
		goto cleanup_group;
	}

	/* Check if values are within 10% of each other */
	unsigned long diff = (resctrl_occupancy > pmu_occupancy) ? 
			     (resctrl_occupancy - pmu_occupancy) :
			     (pmu_occupancy - resctrl_occupancy);
	unsigned long avg = (resctrl_occupancy + pmu_occupancy) / 2;
	double percent_diff = (double)diff * 100.0 / avg;

	if (percent_diff > TOLERANCE_PERCENT) {
		ksft_print_msg("FAIL: Difference %.1f%% exceeds tolerance %d%%\n",
			       percent_diff, TOLERANCE_PERCENT);
		goto cleanup_group;
	}

	ksft_print_msg("PASS: PMU and resctrl measurements within %.1f%% of each other\n",
		       percent_diff);
	ret = 0;

cleanup_group:
	remove_monitoring_group(group_name);
	
	return ret;
}

struct resctrl_test pmu_llc_occupancy_test = {
	.name = "PMU_LLC_OCCUPANCY",
	.group = "pmu",
	.resource = "L3",
	.vendor_specific = 0,
	.feature_check = pmu_llc_occupancy_feature_check,
	.run_test = pmu_llc_occupancy_run_test,
	.cleanup = NULL,
};