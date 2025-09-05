// SPDX-License-Identifier: GPL-2.0
/*
 * Resctrl PMU LLC Occupancy test
 *
 * Test program to verify the resctrl PMU LLC occupancy measurement matches
 * the resctrl filesystem measurement.
 *
 * Test methodology:
 * 1. Parent allocates 256MB buffer and traverses it once before fork
 * 2. Child joins resctrl monitoring group
 * 3. Child allocates and traverses 4MB buffer to fill L2 cache and spill to L3
 * 4. Parent creates cache pressure, waits 2ms, takes baseline LLC measurement
 * 5. Child allocates 1MB buffer and traverses both buffers for 100ms
 * 6. Parent waits 50ms, creates cache pressure, waits 2ms, takes final measurement
 * 7. Verify delta is 1MB ± 15% and resctrl/PMU within 10% of each other
 */

#include "resctrl.h"
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#define RESCTRL_PMU_NAME "resctrl"
#define FLUSH_SIZE_MB 256
#define FLUSH_ARRAY_SIZE (FLUSH_SIZE_MB * MB / sizeof(uint32_t))
#define INITIAL_BUFFER_SIZE_MB 4
#define INITIAL_ARRAY_SIZE (INITIAL_BUFFER_SIZE_MB * MB / sizeof(uint32_t))
#define TEST_BUFFER_SIZE_MB 1
#define TEST_ARRAY_SIZE (TEST_BUFFER_SIZE_MB * MB / sizeof(uint32_t))
#define MEASUREMENT_DELAY_MS 50
#define DELTA_TOLERANCE_PERCENT 15
#define PMU_RESCTRL_TOLERANCE_PERCENT 10

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

/* Child process: Allocate and walk permutations according to new test flow */
static void child_walk_permutation(const char *group_name, int ready_fd, int proceed_fd)
{
	uint32_t *initial_array;
	uint32_t *test_array;
	uint8_t ready = 1;
	uint8_t proceed;
	volatile uint64_t total_checksum = 0;

	/* Phase 1: Join the resctrl monitoring group */
	if (add_pid_to_monitoring_group(group_name, getpid()) < 0) {
		exit(1);
	}

	/* Phase 2: Immediately allocate and traverse 4MB buffer */
	ksft_print_msg("Child: Allocating 4MB initial buffer...\n");
	initial_array = allocate_and_initialize_permutation(INITIAL_ARRAY_SIZE);
	if (!initial_array) {
		ksft_print_msg("Failed to allocate initial array\n");
		exit(1);
	}
	
	/* Traverse the 4MB buffer to fill L2 cache and spill to L3 */
	ksft_print_msg("Child: Traversing 4MB buffer to fill L2 cache...\n");
	for (int i = 0; i < 10; i++) {
		total_checksum += traverse_permutation(initial_array, INITIAL_ARRAY_SIZE);
	}
	
	/* Signal parent that we're ready for baseline measurement */
	ksft_print_msg("Child: Signaling parent ready for baseline measurement\n");
	if (write(ready_fd, &ready, 1) != 1) {
		perror("write ready signal");
		exit(1);
	}
	close(ready_fd);

	/* Keep traversing the 4MB permutation while waiting for parent signal */
	ksft_print_msg("Child: Continuously traversing 4MB buffer to maintain cache occupancy...\n");
	int iteration_count = 0;
	int flags;
	int bytes_read;
	
	/* Set proceed_fd to non-blocking so we can check without blocking */
	flags = fcntl(proceed_fd, F_GETFL, 0);
	fcntl(proceed_fd, F_SETFL, flags | O_NONBLOCK);
	
	while (1) {
		/* Traverse permutation 100 times */
		for (int i = 0; i < 100; i++) {
			total_checksum += traverse_permutation(initial_array, INITIAL_ARRAY_SIZE);
		}
		iteration_count += 100;
		
		/* Check for proceed signal without blocking */
		bytes_read = read(proceed_fd, &proceed, 1);
		if (bytes_read == 1) {
			/* Got the signal, break out of loop */
			ksft_print_msg("Child: Received proceed signal after %d iterations\n", iteration_count);
			break;
		} else if (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			perror("read proceed signal");
			exit(1);
		}
		/* Otherwise continue traversing */
	}
	close(proceed_fd);

	/* Phase 3: Allocate 1MB test buffer */
	ksft_print_msg("Child: Allocating 1MB test buffer...\n");
	test_array = allocate_and_initialize_permutation(TEST_ARRAY_SIZE / 2);  /* Half size for each permutation half */
	if (!test_array) {
		ksft_print_msg("Failed to allocate test array\n");
		exit(1);
	}
	
	/* Traverse both 4MB and 1MB buffers until killed by parent */
	ksft_print_msg("Child: Continuously traversing 4MB and 1MB buffers until killed...\n");
	
	while (1) {
		/* Traverse 4MB buffer */
		total_checksum += traverse_permutation(initial_array, INITIAL_ARRAY_SIZE);
		
		/* Traverse 1MB buffer */
		total_checksum += traverse_permutation(test_array, TEST_ARRAY_SIZE / 2);
	}
	
	/* Final statistics */
	ksft_print_msg("Child: Test completed, final checksum: 0x%lx\n", 
		       (unsigned long)total_checksum);

	/* No cleanup needed - process exits and OS reclaims memory */
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
	pid_t child_pid = -1;
	int ready_pipe[2] = {-1, -1};  /* Child -> Parent: ready signal */
	int proceed_pipe[2] = {-1, -1}; /* Parent -> Child: proceed signal */
	int ret = -1;
	uint8_t ready;
	uint8_t proceed = 1;
	struct timespec ts;
	unsigned long baseline_resctrl = 0, baseline_pmu = 0;
	unsigned long final_resctrl = 0, final_pmu = 0;
	unsigned long delta_resctrl, delta_pmu;
	uint32_t *parent_flush_array = NULL;
	volatile uint64_t parent_checksum = 0;

	ksft_print_msg("Testing PMU LLC occupancy measurement with controlled memory allocation\n");

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
	
	/* Step 1: Parent allocates 256MB array and traverses it once */
	ksft_print_msg("Parent: Allocating and traversing 256MB array before fork...\n");
	parent_flush_array = allocate_and_initialize_permutation(FLUSH_ARRAY_SIZE);
	if (!parent_flush_array) {
		ksft_print_msg("Failed to allocate parent flush array\n");
		goto cleanup_group;
	}
	
	parent_checksum += traverse_permutation(parent_flush_array, FLUSH_ARRAY_SIZE);
	ksft_print_msg("Parent: Initial traversal complete, checksum: 0x%lx\n", (unsigned long)parent_checksum);

	/* Create pipes for bidirectional communication */
	if (pipe(ready_pipe) < 0) {
		perror("pipe ready");
		goto cleanup_group;
	}
	
	if (pipe(proceed_pipe) < 0) {
		perror("pipe proceed");
		goto cleanup_pipes;
	}

	/* Fork child process */
	child_pid = fork();
	if (child_pid < 0) {
		perror("fork");
		goto cleanup_pipes;
	}

	if (child_pid == 0) {
		/* Child process */
		close(ready_pipe[0]);   /* Close read end of ready pipe */
		close(proceed_pipe[1]); /* Close write end of proceed pipe */
		free(parent_flush_array); /* Free parent's array in child */
		child_walk_permutation(group_name, ready_pipe[1], proceed_pipe[0]);
		/* Should not reach here */
		exit(1);
	}

	/* Parent process */
	/* Wait for child to be ready (after 4MB allocation) */
	ksft_print_msg("Parent: Waiting for child to be ready...\n");
	if (read(ready_pipe[0], &ready, 1) != 1) {
		ksft_print_msg("Failed to get ready signal from child\n");
		goto cleanup_child;
	}
	
	/* Step 3: Parent traverses 256MB array once to create cache pressure */
	ksft_print_msg("Parent: Creating cache pressure before baseline measurement...\n");
	parent_checksum += traverse_permutation(parent_flush_array, FLUSH_ARRAY_SIZE);
	
	/* Wait 2 milliseconds */
	ksft_print_msg("Parent: Waiting 2ms before baseline measurement...\n");
	ts.tv_sec = 0;
	ts.tv_nsec = 2 * 1000000;  /* 2ms in nanoseconds */
	nanosleep(&ts, NULL);

	/* Take baseline measurements */
	ksft_print_msg("Parent: Taking baseline measurements...\n");
	if (read_llc_occupancy_from_resctrl(group_name, &baseline_resctrl) < 0) {
		ksft_print_msg("Failed to read baseline resctrl occupancy\n");
		goto cleanup_child;
	}
	
	if (read_llc_occupancy_from_pmu(pmu_type, group_name, &baseline_pmu) < 0) {
		ksft_print_msg("Failed to read baseline PMU occupancy\n");
		goto cleanup_child;
	}

	ksft_print_msg("Parent: Baseline - Resctrl: %lu bytes, PMU: %lu bytes\n", 
		       baseline_resctrl, baseline_pmu);

	/* Step 4: Signal child to allocate 1MB buffer and start traversing */
	ksft_print_msg("Parent: Signaling child to proceed with test...\n");
	if (write(proceed_pipe[1], &proceed, 1) != 1) {
		perror("write proceed signal");
		goto cleanup_child;
	}

	/* Step 5: Wait 50ms, then create cache pressure before second measurement */
	ksft_print_msg("Parent: Waiting %dms before second measurement...\n", MEASUREMENT_DELAY_MS);
	ts.tv_sec = 0;
	ts.tv_nsec = MEASUREMENT_DELAY_MS * 1000000;  /* Convert ms to ns */
	nanosleep(&ts, NULL);
	
	/* Traverse 256MB array once to create cache pressure */
	ksft_print_msg("Parent: Creating cache pressure before final measurement...\n");
	parent_checksum += traverse_permutation(parent_flush_array, FLUSH_ARRAY_SIZE);
	
	/* Wait 2 milliseconds */
	ksft_print_msg("Parent: Waiting 2ms before final measurement...\n");
	ts.tv_sec = 0;
	ts.tv_nsec = 2 * 1000000;  /* 2ms in nanoseconds */
	nanosleep(&ts, NULL);

	/* Take final measurements */
	ksft_print_msg("Parent: Taking final measurements...\n");
	if (read_llc_occupancy_from_resctrl(group_name, &final_resctrl) < 0) {
		ksft_print_msg("Failed to read final resctrl occupancy\n");
		goto cleanup_child;
	}
	
	if (read_llc_occupancy_from_pmu(pmu_type, group_name, &final_pmu) < 0) {
		ksft_print_msg("Failed to read final PMU occupancy\n");
		goto cleanup_child;
	}

	ksft_print_msg("Parent: Final - Resctrl: %lu bytes, PMU: %lu bytes\n", 
		       final_resctrl, final_pmu);
	
	/* Calculate deltas */
	delta_resctrl = final_resctrl - baseline_resctrl;
	delta_pmu = final_pmu - baseline_pmu;
	
	ksft_print_msg("\n=== Test Results ===\n");
	ksft_print_msg("Baseline - Resctrl: %lu bytes, PMU: %lu bytes\n", 
		       baseline_resctrl, baseline_pmu);
	ksft_print_msg("Final    - Resctrl: %lu bytes, PMU: %lu bytes\n", 
		       final_resctrl, final_pmu);
	ksft_print_msg("Delta    - Resctrl: %lu bytes, PMU: %lu bytes\n", 
		       delta_resctrl, delta_pmu);
	
	/* Expected delta is 1MB */
	unsigned long expected_delta = TEST_BUFFER_SIZE_MB * MB;
	
	/* Check if deltas are within 15% of expected 1MB */
	unsigned long resctrl_diff = (delta_resctrl > expected_delta) ? 
				      (delta_resctrl - expected_delta) :
				      (expected_delta - delta_resctrl);
	double resctrl_percent_diff = (double)resctrl_diff * 100.0 / expected_delta;
	
	unsigned long pmu_diff = (delta_pmu > expected_delta) ? 
				  (delta_pmu - expected_delta) :
				  (expected_delta - delta_pmu);
	double pmu_percent_diff = (double)pmu_diff * 100.0 / expected_delta;
	
	ksft_print_msg("\nDelta vs Expected (1MB):\n");
	ksft_print_msg("  Resctrl delta: %.1f%% difference from expected\n", resctrl_percent_diff);
	ksft_print_msg("  PMU delta:     %.1f%% difference from expected\n", pmu_percent_diff);
	
	if (resctrl_percent_diff > DELTA_TOLERANCE_PERCENT) {
		ksft_print_msg("FAIL: Resctrl delta difference %.1f%% exceeds tolerance %d%%\n",
			       resctrl_percent_diff, DELTA_TOLERANCE_PERCENT);
		goto cleanup_child;
	}
	
	if (pmu_percent_diff > DELTA_TOLERANCE_PERCENT) {
		ksft_print_msg("FAIL: PMU delta difference %.1f%% exceeds tolerance %d%%\n",
			       pmu_percent_diff, DELTA_TOLERANCE_PERCENT);
		goto cleanup_child;
	}
	
	/* Check if resctrl and PMU measurements are within 10% of each other */
	unsigned long measurement_diff = (delta_resctrl > delta_pmu) ? 
					  (delta_resctrl - delta_pmu) :
					  (delta_pmu - delta_resctrl);
	double measurement_percent_diff = (double)measurement_diff * 100.0 / ((delta_resctrl + delta_pmu) / 2);
	
	ksft_print_msg("\nResctrl vs PMU comparison:\n");
	ksft_print_msg("  Difference: %.1f%%\n", measurement_percent_diff);
	
	if (measurement_percent_diff > PMU_RESCTRL_TOLERANCE_PERCENT) {
		ksft_print_msg("FAIL: Resctrl/PMU difference %.1f%% exceeds tolerance %d%%\n",
			       measurement_percent_diff, PMU_RESCTRL_TOLERANCE_PERCENT);
		goto cleanup_child;
	}

	ksft_print_msg("\nPASS: Both deltas within %d%% of expected 1MB\n", DELTA_TOLERANCE_PERCENT);
	ksft_print_msg("PASS: PMU and resctrl measurements within %.1f%% of each other\n",
		       measurement_percent_diff);
	ret = 0;

cleanup_child:
	if (child_pid > 0) {
		kill(child_pid, SIGKILL);
		waitpid(child_pid, NULL, 0);
	}

cleanup_pipes:
	if (ready_pipe[0] >= 0)
		close(ready_pipe[0]);
	if (ready_pipe[1] >= 0)
		close(ready_pipe[1]);
	if (proceed_pipe[0] >= 0)
		close(proceed_pipe[0]);
	if (proceed_pipe[1] >= 0)
		close(proceed_pipe[1]);

cleanup_group:
	if (parent_flush_array) {
		ksft_print_msg("Parent: Final checksum: 0x%lx\n", (unsigned long)parent_checksum);
		free(parent_flush_array);
	}
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