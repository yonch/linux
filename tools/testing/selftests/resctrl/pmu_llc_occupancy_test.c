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
#include <string.h>

#define RESCTRL_PMU_NAME "resctrl"
#define ARRAY_SIZE_MB 1
#define PERM_ARRAY_SIZE (ARRAY_SIZE_MB * MB / sizeof(uint32_t))
#define MIN_EXPECTED_OCCUPANCY (1600 * 1024)  // 1.6 MB (two 1MB arrays, some may be evicted)
#define MAX_EXPECTED_OCCUPANCY (2200 * 1024)  // 2.2 MB (two 1MB arrays plus some overhead)
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
 * 
 * @perm: Array to store the permutation (size n)
 * @pool: Pre-allocated pool array (size n-1), MANDATORY - will be modified
 * @n: Size of the permutation
 */
static void create_single_cycle_permutation(uint32_t *perm, uint32_t *pool, size_t n)
{
	size_t pool_size;
	size_t idx;
	size_t i;

	/* Pool must be provided */
	if (!pool) {
		ksft_print_msg("ERROR: pool parameter is mandatory\n");
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

/* Child process: Walk the permutation continuously */
static void child_walk_permutation(const char *group_name, size_t n, int ready_fd)
{
	uint32_t *flush_perm, *flush_pool;
	uint32_t *perm_array1, *perm_array2;
	struct timespec start, now, delay_ts;
	size_t idx;
	size_t iterations = 0;
	uint8_t ready = 1;
	size_t flush_size = (256 * MB) / sizeof(uint32_t);  /* 256MB array */
	char path[512];
	FILE *file;
	char *line = NULL;
	size_t len = 0;

	/* Step 1: Create and walk a huge 256MB permutation to flush the cache */
	ksft_print_msg("Creating 256MB flush permutation to evict cache...\n");
	flush_perm = malloc(flush_size * sizeof(uint32_t));
	if (!flush_perm) {
		perror("malloc flush_perm");
		exit(1);
	}
	
	/* Allocate pool for flush permutation (256MB - 4 bytes) */
	flush_pool = malloc((flush_size - 1) * sizeof(uint32_t));
	if (!flush_pool) {
		perror("malloc flush_pool");
		free(flush_perm);
		exit(1);
	}
	
	/* Generate the flush permutation */
	create_single_cycle_permutation(flush_perm, flush_pool, flush_size);
	
	/* Walk through the flush permutation once to ensure it's in cache */
	ksft_print_msg("Walking flush permutation to ensure cache eviction...\n");
	idx = 0;
	volatile uint64_t flush_checksum = 0;  /* Prevent optimization */
	for (size_t i = 0; i < flush_size; i++) {
		flush_checksum += flush_perm[idx];
		idx = flush_perm[idx];
	}
	/* Use the checksum to ensure it's not optimized out */
	ksft_print_msg("Flush walk checksum: 0x%lx\n", (unsigned long)flush_checksum);
	
	/* Keep BOTH flush permutation and pool allocated - prevents memory reuse */
	ksft_print_msg("Keeping 512MB (256MB flush array + 256MB pool) allocated to prevent memory reuse\n");

	/* Step 2: Join the resctrl monitoring group */
	if (add_pid_to_monitoring_group(group_name, getpid()) < 0) {
		free(flush_perm);
		free(flush_pool);
		exit(1);
	}

	/* Step 3: Wait 100ms to ensure all measurements are set up */
	ksft_print_msg("Child waiting 100ms after joining group...\n");
	delay_ts.tv_sec = 0;
	delay_ts.tv_nsec = 100 * 1000000;  /* 100ms */
	nanosleep(&delay_ts, NULL);

	/* Step 4: Allocate two 1MB arrays */
	ksft_print_msg("Allocating two 1MB arrays for permutations...\n");
	perm_array1 = malloc(n * sizeof(uint32_t));
	if (!perm_array1) {
		perror("malloc perm_array1");
		free(flush_perm);
		free(flush_pool);
		exit(1);
	}
	
	/* Array2 will be used as pool initially (n elements, though only n-1 needed for pool) */
	perm_array2 = malloc(n * sizeof(uint32_t));
	if (!perm_array2) {
		perror("malloc perm_array2");
		free(flush_perm);
		free(flush_pool);
		free(perm_array1);
		exit(1);
	}
	
	/* Step 5: Create permutation in array1 using array2 as the pool */
	ksft_print_msg("Creating permutation in array1 using array2 as pool...\n");
	create_single_cycle_permutation(perm_array1, perm_array2, n);
	
	/* Step 6: Copy the permutation from array1 to array2 (now we have two replicas) */
	ksft_print_msg("Copying permutation to create second replica...\n");
	memcpy(perm_array2, perm_array1, n * sizeof(uint32_t));

	/* Read and print the tasks file to verify we're in the group */
	snprintf(path, sizeof(path), "%s/mon_groups/%s/tasks", RESCTRL_PATH, group_name);
	file = fopen(path, "r");
	if (file) {
		ksft_print_msg("Child: Contents of %s:\n", path);
		while (getline(&line, &len, file) > 0) {
			ksft_print_msg("  Task PID: %s", line);
		}
		fclose(file);
		free(line);
	} else {
		ksft_print_msg("Child: Failed to read tasks file at %s\n", path);
	}

	/* Signal parent that we're ready */
	if (write(ready_fd, &ready, 1) != 1) {
		perror("write ready signal");
		free(flush_perm);
		free(flush_pool);
		free(perm_array1);
		free(perm_array2);
		exit(1);
	}
	close(ready_fd);

	/* Get start time */
	clock_gettime(CLOCK_MONOTONIC, &start);

	/* Step 7: Walk both permutation arrays continuously */
	ksft_print_msg("Walking both 1MB permutation arrays...\n");
	size_t idx1 = 0, idx2 = 0;
	volatile uint64_t checksum = 0;  /* Use volatile to prevent optimization */
	
	while (1) {
		/* Walk array1 */
		checksum += perm_array1[idx1];
		idx1 = perm_array1[idx1];
		
		/* Walk array2 */
		checksum += perm_array2[idx2];
		idx2 = perm_array2[idx2];
		
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
	
	/* Output the checksum to ensure it's not optimized out */
	ksft_print_msg("Permutation walk completed: %lu iterations, checksum: 0x%lx\n", 
		       iterations, (unsigned long)checksum);

	free(flush_perm);
	free(flush_pool);
	free(perm_array1);
	free(perm_array2);
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
	unsigned long resctrl_occupancy, pmu_occupancy;
	int pmu_type;
	pid_t child_pid;
	int pipe_fds[2];
	int ret = -1;
	uint8_t ready;
	struct timespec ts;

	ksft_print_msg("Testing PMU LLC occupancy measurement with debugging\n");

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

	/* Perform periodic measurements every 100ms */
	int measurement_count = 0;
	int max_measurements = 5;  /* 5 measurements at 100ms intervals = 500ms total */
	unsigned long periodic_llc_resctrl[5], periodic_llc_pmu[5];
	unsigned long periodic_mbm_total_resctrl[5], periodic_mbm_local_resctrl[5];
	unsigned long periodic_mbm_total_pmu[5], periodic_mbm_local_pmu[5];
	
	for (measurement_count = 0; measurement_count < max_measurements; measurement_count++) {
		/* Wait 100ms */
		ts.tv_sec = 0;
		ts.tv_nsec = 100 * 1000000;  /* 100ms */
		nanosleep(&ts, NULL);
		
		ksft_print_msg("\n=== Measurement %d (at %dms) ===\n", 
			       measurement_count + 1, (measurement_count + 1) * 100);
		
		/* Read LLC occupancy from resctrl */
		if (read_llc_occupancy_from_resctrl(group_name, &periodic_llc_resctrl[measurement_count]) < 0) {
			periodic_llc_resctrl[measurement_count] = 0;
		}
		ksft_print_msg("  LLC Resctrl FS: %lu bytes\n", periodic_llc_resctrl[measurement_count]);
		
		/* Read LLC occupancy from PMU */
		if (read_llc_occupancy_from_pmu(pmu_type, group_name, &periodic_llc_pmu[measurement_count]) < 0) {
			periodic_llc_pmu[measurement_count] = 0;
		}
		ksft_print_msg("  LLC PMU:        %lu bytes\n", periodic_llc_pmu[measurement_count]);
		
		/* Read MBM from resctrl */
		if (read_mbm_from_resctrl(group_name, &periodic_mbm_total_resctrl[measurement_count], 
					   &periodic_mbm_local_resctrl[measurement_count]) < 0) {
			periodic_mbm_total_resctrl[measurement_count] = 0;
			periodic_mbm_local_resctrl[measurement_count] = 0;
		}
		ksft_print_msg("  MBM Total Resctrl: %lu bytes\n", periodic_mbm_total_resctrl[measurement_count]);
		ksft_print_msg("  MBM Local Resctrl: %lu bytes\n", periodic_mbm_local_resctrl[measurement_count]);
		
		/* Read MBM from PMU */
		if (read_mbm_from_pmu(pmu_type, group_name, &periodic_mbm_total_pmu[measurement_count],
				      &periodic_mbm_local_pmu[measurement_count]) < 0) {
			periodic_mbm_total_pmu[measurement_count] = 0;
			periodic_mbm_local_pmu[measurement_count] = 0;
		}
		ksft_print_msg("  MBM Total PMU:     %lu bytes\n", periodic_mbm_total_pmu[measurement_count]);
		ksft_print_msg("  MBM Local PMU:     %lu bytes\n", periodic_mbm_local_pmu[measurement_count]);
	}
	
	/* Use the last measurements for validation */
	resctrl_occupancy = periodic_llc_resctrl[max_measurements - 1];
	pmu_occupancy = periodic_llc_pmu[max_measurements - 1];
	
	/* Wait for child to complete */
	waitpid(child_pid, NULL, 0);
	
	/* Print summary of all measurements */
	ksft_print_msg("\n=== Measurement Summary ===\n");
	for (int i = 0; i < max_measurements; i++) {
		ksft_print_msg("Time %dms: LLC(resctrl=%lu, pmu=%lu), MBM_total(resctrl=%lu, pmu=%lu), MBM_local(resctrl=%lu, pmu=%lu)\n",
			       (i + 1) * 100,
			       periodic_llc_resctrl[i], periodic_llc_pmu[i],
			       periodic_mbm_total_resctrl[i], periodic_mbm_total_pmu[i],
			       periodic_mbm_local_resctrl[i], periodic_mbm_local_pmu[i]);
	}

	/* Print final results */
	ksft_print_msg("\n=== Final LLC Occupancy Results ===\n");
	ksft_print_msg("  Resctrl FS: %lu bytes\n", resctrl_occupancy);
	ksft_print_msg("  PMU:        %lu bytes\n", pmu_occupancy);

	/* Check if values are within expected range */
	if (resctrl_occupancy < MIN_EXPECTED_OCCUPANCY || 
	    resctrl_occupancy > MAX_EXPECTED_OCCUPANCY) {
		ksft_print_msg("FAIL: Resctrl occupancy %lu outside expected range [%d, %d]\n",
			       resctrl_occupancy, MIN_EXPECTED_OCCUPANCY, MAX_EXPECTED_OCCUPANCY);
		goto cleanup_group;
	}

	if (pmu_occupancy < MIN_EXPECTED_OCCUPANCY || 
	    pmu_occupancy > MAX_EXPECTED_OCCUPANCY) {
		ksft_print_msg("FAIL: PMU occupancy %lu outside expected range [%d, %d]\n",
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