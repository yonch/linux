// SPDX-License-Identifier: GPL-2.0
/*
 * Resctrl PMU LLC Occupancy test
 *
 * Test program to verify the resctrl PMU LLC occupancy measurement matches
 * the resctrl filesystem measurement.
 *
 * Test methodology:
 * 1. Child process first allocates 256MB buffer to flush cache
 * 2. Child then dynamically allocates 1MB arrays every 100ms (up to 200 arrays over 20 seconds)
 * 3. Child continuously traverses all allocated arrays
 * 4. Parent measures LLC occupancy every 10ms via both resctrl FS and PMU
 * 5. All measurements are collected and printed at the end
 */

#include "resctrl.h"
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <string.h>

#define RESCTRL_PMU_NAME "resctrl"
#define ARRAY_SIZE_MB 1
#define PERM_ARRAY_SIZE (ARRAY_SIZE_MB * MB / sizeof(uint32_t))
#define FLUSH_SIZE_MB 256
#define FLUSH_ARRAY_SIZE (FLUSH_SIZE_MB * MB / sizeof(uint32_t))
#define MIN_EXPECTED_OCCUPANCY (100 * 1024)  // Start with low expectation
#define MAX_EXPECTED_OCCUPANCY (20 * MB)     // Up to 20MB for 20 arrays
#define TOLERANCE_PERCENT 10
#define ITERATIONS_PER_CHECK 1000
#define TEST_DURATION_MS 20000  // 20 seconds total
#define ALLOCATION_INTERVAL_MS 100  // Allocate new array every 100ms
#define MEASUREMENT_INTERVAL_MS 10  // Parent measures every 10ms
#define MAX_ARRAYS 200  // Maximum number of 1MB arrays to allocate

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
 * Allocate and initialize a single-cycle permutation.
 * Creates a 2n-sized allocation where the first half contains the permutation
 * and the second half is a duplicate copy for traversal.
 * 
 * @n: Number of elements in the permutation
 * @return: Pointer to allocated memory (2n elements total) or NULL on failure
 */
static uint32_t *allocate_and_initialize_permutation(size_t n)
{
	uint32_t *array;
	uint32_t *pool;
	size_t pool_size;
	size_t idx;
	size_t i;

	/* Allocate 2n elements */
	array = malloc(2 * n * sizeof(uint32_t));
	if (!array) {
		ksft_print_msg("Failed to allocate permutation array\n");
		return NULL;
	}

	/* Use second half as temporary pool */
	pool = array + n;

	/* Initialize pool with values 2..n */
	for (i = 0; i < n - 1; i++) {
		pool[i] = i + 2;
	}
	pool_size = n - 1;

	/* Start at index 1 (0-indexed, so position 0) */
	idx = 0;

	/* Build the permutation in first half */
	while (pool_size > 0) {
		/* Draw random member from pool */
		size_t rand_idx = rand() % pool_size;
		uint32_t m = pool[rand_idx];
		
		/* Assign it to current index */
		array[idx] = m - 1;  /* Convert to 0-indexed */
		
		/* Remove from pool by copying last element to this position */
		pool[rand_idx] = pool[pool_size - 1];
		pool_size--;
		
		/* Next index is the value we just picked */
		idx = m - 1;  /* Convert to 0-indexed */
	}
	
	/* Assign 1 (0 in 0-indexed) to the last spot */
	array[idx] = 0;

	/* Copy first half to second half */
	memcpy(array + n, array, n * sizeof(uint32_t));

	return array;
}

/*
 * Traverse a permutation array.
 * Traverses both halves of the allocated 2n array.
 * 
 * @array: Pointer to the permutation array (2n elements)
 * @n: Number of elements in each half
 * @return: Checksum value (to prevent optimization)
 */
static uint64_t traverse_permutation(uint32_t *array, size_t n)
{
	volatile uint64_t checksum = 0;
	size_t idx;
	size_t i;

	/* Traverse first half */
	idx = 0;
	for (i = 0; i < n; i++) {
		checksum += array[idx];
		idx = array[idx];
	}

	/* Traverse second half */
	idx = n;
	for (i = 0; i < n; i++) {
		checksum += array[idx];
		idx = array[idx] + n;  /* Next index in second half */
	}

	return checksum;
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

/* Child process: Dynamically allocate and walk permutations */
static void child_walk_permutation(const char *group_name, size_t n, int ready_fd)
{
	uint32_t *flush_array;
	uint32_t *perm_arrays[MAX_ARRAYS];
	struct timespec start, now, last_allocation, delay_ts;
	uint8_t ready = 1;
	int num_arrays = 0;
	volatile uint64_t total_checksum = 0;
	int i;

	/* Initialize array pointers */
	for (i = 0; i < MAX_ARRAYS; i++) {
		perm_arrays[i] = NULL;
	}

	/* Step 1: Create and walk a huge 256MB permutation to flush the cache */
	ksft_print_msg("Creating 256MB flush permutation to evict cache...\n");
	flush_array = allocate_and_initialize_permutation(FLUSH_ARRAY_SIZE);
	if (!flush_array) {
		ksft_print_msg("Failed to allocate flush array\n");
		exit(1);
	}
	
	/* Walk through the flush permutation once to flush cache */
	ksft_print_msg("Walking flush permutation to ensure cache eviction...\n");
	total_checksum = traverse_permutation(flush_array, FLUSH_ARRAY_SIZE);
	ksft_print_msg("Flush walk checksum: 0x%lx\n", (unsigned long)total_checksum);
	
	/* Keep flush array allocated to prevent memory reuse */
	ksft_print_msg("Keeping 512MB flush array allocated\n");

	/* Step 2: Join the resctrl monitoring group */
	if (add_pid_to_monitoring_group(group_name, getpid()) < 0) {
		free(flush_array);
		exit(1);
	}

	/* Step 3: Wait 100ms to ensure all measurements are set up */
	ksft_print_msg("Child waiting 100ms after joining group...\n");
	delay_ts.tv_sec = 0;
	delay_ts.tv_nsec = 100 * 1000000;  /* 100ms */
	nanosleep(&delay_ts, NULL);

	/* Signal parent that we're ready */
	if (write(ready_fd, &ready, 1) != 1) {
		perror("write ready signal");
		free(flush_array);
		exit(1);
	}
	close(ready_fd);

	/* Get start time */
	clock_gettime(CLOCK_MONOTONIC, &start);
	last_allocation = start;

	ksft_print_msg("Starting dynamic allocation and traversal for %d seconds...\n", 
		       TEST_DURATION_MS / 1000);
	
	/* Main loop: allocate new arrays every 100ms and traverse all */
	while (1) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
				  (now.tv_nsec - start.tv_nsec) / 1000000;
		
		/* Check if test duration has elapsed */
		if (elapsed_ms >= TEST_DURATION_MS) {
			break;
		}
		
		/* Check if it's time to allocate a new array */
		long since_last_alloc = (now.tv_sec - last_allocation.tv_sec) * 1000 +
					(now.tv_nsec - last_allocation.tv_nsec) / 1000000;
		
		if (since_last_alloc >= ALLOCATION_INTERVAL_MS && num_arrays < MAX_ARRAYS) {
			/* Allocate new 1MB permutation array */
			perm_arrays[num_arrays] = allocate_and_initialize_permutation(n);
			if (perm_arrays[num_arrays]) {
				num_arrays++;
				ksft_print_msg("Allocated array %d at %ld ms\n", num_arrays, elapsed_ms);
				last_allocation = now;
			}
		}
		
		/* Traverse all allocated arrays */
		for (i = 0; i < num_arrays; i++) {
			if (perm_arrays[i]) {
				total_checksum += traverse_permutation(perm_arrays[i], n);
			}
		}
	}
	
	/* Final statistics */
	ksft_print_msg("Test completed: %d arrays allocated, checksum: 0x%lx\n", 
		       num_arrays, (unsigned long)total_checksum);

	/* Cleanup */
	free(flush_array);
	for (i = 0; i < num_arrays; i++) {
		if (perm_arrays[i]) {
			free(perm_arrays[i]);
		}
	}
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

static int read_mbm_from_resctrl(const char *group_name, unsigned long *mbm_total, unsigned long *mbm_local)
{
	char path[512];
	FILE *file;
	char *line = NULL;
	size_t len = 0;
	int ret = -1;

	*mbm_total = 0;
	*mbm_local = 0;

	/* Try different domain IDs until we find one that exists */
	for (int domain = 0; domain < 4; domain++) {
		/* Read MBM total */
		snprintf(path, sizeof(path), "%s/mon_groups/%s/mon_data/mon_L3_%02d/mbm_total_bytes",
			 RESCTRL_PATH, group_name, domain);
		
		file = fopen(path, "r");
		if (file) {
			if (getline(&line, &len, file) > 0) {
				*mbm_total = strtoul(line, NULL, 10);
				ret = 0;
			}
			fclose(file);
			free(line);
			line = NULL;
			len = 0;
		}

		/* Read MBM local */
		snprintf(path, sizeof(path), "%s/mon_groups/%s/mon_data/mon_L3_%02d/mbm_local_bytes",
			 RESCTRL_PATH, group_name, domain);
		
		file = fopen(path, "r");
		if (file) {
			if (getline(&line, &len, file) > 0) {
				*mbm_local = strtoul(line, NULL, 10);
				ret = 0;
			}
			fclose(file);
			free(line);
			line = NULL;
			len = 0;
		}

		if (ret == 0)
			break;
	}
	
	if (ret < 0) {
		ksft_print_msg("Failed to read MBM from resctrl\n");
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

static int read_mbm_from_pmu(int pmu_type, const char *group_name, 
			      unsigned long *mbm_total, unsigned long *mbm_local)
{
	struct perf_event_attr pe = {0};
	char path[512];
	int mon_fd_total = -1, mon_fd_local = -1;
	int perf_fd_total = -1, perf_fd_local = -1;
	int ret = -1;
	int domain;

	*mbm_total = 0;
	*mbm_local = 0;

	/* Find domain with MBM files */
	for (domain = 0; domain < 4; domain++) {
		snprintf(path, sizeof(path), "%s/mon_groups/%s/mon_data/mon_L3_%02d/mbm_total_bytes",
			 RESCTRL_PATH, group_name, domain);
		mon_fd_total = open(path, O_RDONLY);
		if (mon_fd_total >= 0)
			break;
	}

	if (mon_fd_total < 0) {
		ksft_print_msg("Failed to open MBM total monitoring file for PMU\n");
		return -1;
	}

	/* Open MBM local for same domain */
	snprintf(path, sizeof(path), "%s/mon_groups/%s/mon_data/mon_L3_%02d/mbm_local_bytes",
		 RESCTRL_PATH, group_name, domain);
	mon_fd_local = open(path, O_RDONLY);
	if (mon_fd_local < 0) {
		ksft_print_msg("Failed to open MBM local monitoring file for PMU\n");
		close(mon_fd_total);
		return -1;
	}

	/* Setup perf event for MBM total */
	memset(&pe, 0, sizeof(pe));
	pe.type = pmu_type;
	pe.config = mon_fd_total;
	pe.size = sizeof(pe);
	pe.disabled = 0;
	pe.exclude_kernel = 0;
	pe.exclude_hv = 0;

	perf_fd_total = perf_event_open(&pe, -1, 0, -1, 0);
	if (perf_fd_total < 0) {
		ksft_print_msg("Failed to open perf event for MBM total: %s\n", strerror(errno));
		goto cleanup;
	}

	/* Setup perf event for MBM local */
	pe.config = mon_fd_local;
	perf_fd_local = perf_event_open(&pe, -1, 0, -1, 0);
	if (perf_fd_local < 0) {
		ksft_print_msg("Failed to open perf event for MBM local: %s\n", strerror(errno));
		goto cleanup;
	}

	/* Read counter values */
	uint64_t value;
	
	if (read(perf_fd_total, &value, sizeof(value)) == sizeof(value)) {
		*mbm_total = value;
		ret = 0;
	} else {
		ksft_print_msg("Failed to read MBM total PMU counter\n");
	}

	if (read(perf_fd_local, &value, sizeof(value)) == sizeof(value)) {
		*mbm_local = value;
	} else {
		ksft_print_msg("Failed to read MBM local PMU counter\n");
		ret = -1;
	}

cleanup:
	if (perf_fd_total >= 0)
		close(perf_fd_total);
	if (perf_fd_local >= 0)
		close(perf_fd_local);
	if (mon_fd_total >= 0)
		close(mon_fd_total);
	if (mon_fd_local >= 0)
		close(mon_fd_local);
	
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
	int pmu_type;
	pid_t child_pid;
	int pipe_fds[2];
	int ret = -1;
	uint8_t ready;
	struct timespec ts, test_start;
	
	/* Arrays to store all measurements */
	int max_measurements = (TEST_DURATION_MS / MEASUREMENT_INTERVAL_MS) + 10;
	unsigned long *llc_resctrl = calloc(max_measurements, sizeof(unsigned long));
	unsigned long *llc_pmu = calloc(max_measurements, sizeof(unsigned long));
	unsigned long *timestamps = calloc(max_measurements, sizeof(unsigned long));
	int measurement_count = 0;

	if (!llc_resctrl || !llc_pmu || !timestamps) {
		ksft_print_msg("Failed to allocate measurement arrays\n");
		free(llc_resctrl);
		free(llc_pmu);
		free(timestamps);
		return -1;
	}

	ksft_print_msg("Testing PMU LLC occupancy measurement with dynamic allocation\n");

	/* Find the resctrl PMU type */
	pmu_type = find_pmu_type(RESCTRL_PMU_NAME);
	if (pmu_type < 0) {
		ksft_print_msg("Resctrl PMU not found\n");
		free(llc_resctrl);
		free(llc_pmu);
		free(timestamps);
		return -1;
	}

	/* Create monitoring group */
	if (create_monitoring_group(group_name) < 0) {
		free(llc_resctrl);
		free(llc_pmu);
		free(timestamps);
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

	ksft_print_msg("Child process (PID %d) ready, starting measurements\n", child_pid);

	/* Record test start time */
	clock_gettime(CLOCK_MONOTONIC, &test_start);
	
	/* Perform measurements every MEASUREMENT_INTERVAL_MS */
	while (1) {
		/* Wait for next measurement interval */
		ts.tv_sec = 0;
		ts.tv_nsec = MEASUREMENT_INTERVAL_MS * 1000000;  /* Convert ms to ns */
		nanosleep(&ts, NULL);
		
		/* Check elapsed time */
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		long elapsed_ms = (now.tv_sec - test_start.tv_sec) * 1000 +
				  (now.tv_nsec - test_start.tv_nsec) / 1000000;
		
		if (elapsed_ms >= TEST_DURATION_MS || measurement_count >= max_measurements - 1) {
			break;
		}
		
		/* Record timestamp */
		timestamps[measurement_count] = elapsed_ms;
		
		/* Read LLC occupancy from resctrl */
		if (read_llc_occupancy_from_resctrl(group_name, &llc_resctrl[measurement_count]) < 0) {
			llc_resctrl[measurement_count] = 0;
		}
		
		/* Read LLC occupancy from PMU */
		if (read_llc_occupancy_from_pmu(pmu_type, group_name, &llc_pmu[measurement_count]) < 0) {
			llc_pmu[measurement_count] = 0;
		}
		
		measurement_count++;
	}
	
	/* Wait for child to complete */
	waitpid(child_pid, NULL, 0);
	
	/* Print all measurements at once */
	ksft_print_msg("\n=== All Measurements (LLC Occupancy in bytes) ===\n");
	ksft_print_msg("Time(ms)\tResctrl\t\tPMU\n");
	for (int i = 0; i < measurement_count; i++) {
		ksft_print_msg("%lu\t\t%lu\t\t%lu\n", 
			       timestamps[i], llc_resctrl[i], llc_pmu[i]);
	}
	
	/* Analyze results - use average of last 10 measurements */
	int analyze_start = (measurement_count > 10) ? measurement_count - 10 : 0;
	unsigned long avg_resctrl = 0, avg_pmu = 0;
	for (int i = analyze_start; i < measurement_count; i++) {
		avg_resctrl += llc_resctrl[i];
		avg_pmu += llc_pmu[i];
	}
	int analyze_count = measurement_count - analyze_start;
	avg_resctrl /= analyze_count;
	avg_pmu /= analyze_count;
	
	ksft_print_msg("\n=== Final Analysis (average of last %d measurements) ===\n", analyze_count);
	ksft_print_msg("  Average Resctrl: %lu bytes\n", avg_resctrl);
	ksft_print_msg("  Average PMU:     %lu bytes\n", avg_pmu);
	
	/* Check if values are reasonable (we don't have strict bounds anymore) */
	if (avg_resctrl == 0 || avg_pmu == 0) {
		ksft_print_msg("FAIL: Got zero measurements\n");
		goto cleanup_group;
	}
	
	/* Check if values are within tolerance of each other */
	unsigned long diff = (avg_resctrl > avg_pmu) ? 
			     (avg_resctrl - avg_pmu) :
			     (avg_pmu - avg_resctrl);
	double percent_diff = (double)diff * 100.0 / ((avg_resctrl + avg_pmu) / 2);

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
	free(llc_resctrl);
	free(llc_pmu);
	free(timestamps);
	
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