// SPDX-License-Identifier: GPL-2.0-only
/*
 * Resctrl PMU support
 * - Enables perf event access to resctrl cache occupancy monitoring
 *
 * This provides a perf PMU interface to read cache occupancy from resctrl
 * monitoring groups using file descriptors for group identification.
 */

#define pr_fmt(fmt) "resctrl_pmu: " fmt

#include <linux/kernel.h>
#include <linux/perf_event.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/err.h>
#include "internal.h"

/*
 * PMU type will be dynamically assigned by perf_pmu_register
 */
static struct pmu resctrl_pmu;

/*
 * Event private data - stores information about the monitored resctrl group
 */
struct resctrl_pmu_event {
	struct file *mon_file;		/* File descriptor to monitoring file */
	char *mon_path;			/* Path extracted from file descriptor */
};

/*
 * Get the file path from a file descriptor for debugging
 */
static char *get_fd_path(int fd)
{
	struct file *file;
	char *path_buf, *path_str = NULL;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);

	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path_buf) {
		fput(file);
		return ERR_PTR(-ENOMEM);
	}

	path_str = d_path(&file->f_path, path_buf, PATH_MAX);
	if (IS_ERR(path_str)) {
		kfree(path_buf);
		fput(file);
		return path_str;
	}

	/* Make a copy of the path string */
	path_str = kstrdup(path_str, GFP_KERNEL);
	kfree(path_buf);
	fput(file);

	return path_str;
}

/*
 * Initialize a new resctrl perf event
 * The config field contains the file descriptor of the monitoring file
 */
static int resctrl_event_init(struct perf_event *event)
{
	struct resctrl_pmu_event *resctrl_event;
	char *path;
	int fd;

	/* Only accept events for this PMU */
	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	/* No sampling support */
	if (is_sampling_event(event))
		return -EINVAL;

	/* No filtering support */
	if (event->attr.exclude_user || event->attr.exclude_kernel ||
	    event->attr.exclude_hv || event->attr.exclude_idle)
		return -EINVAL;

	/* Extract file descriptor from config */
	fd = (int)event->attr.config;
	if (fd < 0)
		return -EINVAL;

	/* Get the file path for debugging */
	path = get_fd_path(fd);
	if (IS_ERR(path))
		return PTR_ERR(path);

	/* Print the path for testing/debugging */
	pr_info("PMU event opened for fd %d, path: %s\n", fd, path);

	/* Allocate our private event data */
	resctrl_event = kzalloc(sizeof(*resctrl_event), GFP_KERNEL);
	if (!resctrl_event) {
		kfree(path);
		return -ENOMEM;
	}

	resctrl_event->mon_path = path;
	event->pmu_private = resctrl_event;

	return 0;
}

/*
 * Clean up event resources - called from del function
 */
static void resctrl_event_cleanup(struct perf_event *event)
{
	struct resctrl_pmu_event *resctrl_event = event->pmu_private;

	if (resctrl_event) {
		kfree(resctrl_event->mon_path);
		kfree(resctrl_event);
		event->pmu_private = NULL;
	}
}

/*
 * Add event to PMU (enable monitoring)
 */
static int resctrl_event_add(struct perf_event *event, int flags)
{
	/* Currently just a stub - would setup actual monitoring here */
	return 0;
}

/*
 * Remove event from PMU (disable monitoring)
 */
static void resctrl_event_del(struct perf_event *event, int flags)
{
	/* Clean up our private resources */
	resctrl_event_cleanup(event);
}

/*
 * Start event counting
 */
static void resctrl_event_start(struct perf_event *event, int flags)
{
	/* Currently just a stub - would start monitoring here */
}

/*
 * Stop event counting
 */
static void resctrl_event_stop(struct perf_event *event, int flags)
{
	/* Currently just a stub - would stop monitoring here */
}

/*
 * Read current counter value
 */
static void resctrl_event_update(struct perf_event *event)
{
	/* Currently just a stub - would read actual cache occupancy here */
	local64_set(&event->hw.prev_count, 0);
}

/*
 * Main PMU structure
 */
static struct pmu resctrl_pmu = {
	.task_ctx_nr	= perf_invalid_context,  /* System-wide only */
	.event_init	= resctrl_event_init,
	.add		= resctrl_event_add,
	.del		= resctrl_event_del,
	.start		= resctrl_event_start,
	.stop		= resctrl_event_stop,
	.read		= resctrl_event_update,
	.capabilities	= PERF_PMU_CAP_NO_INTERRUPT | PERF_PMU_CAP_NO_EXCLUDE,
};

/*
 * Initialize and register the resctrl PMU
 */
int __init resctrl_pmu_init(void)
{
	int ret;

	/* Register the PMU with perf subsystem */
	ret = perf_pmu_register(&resctrl_pmu, "resctrl", -1);
	if (ret) {
		pr_err("Failed to register resctrl PMU: %d\n", ret);
		return ret;
	}

	pr_info("Registered resctrl PMU with type %d\n", resctrl_pmu.type);
	return 0;
}

/*
 * Cleanup the resctrl PMU
 */
void resctrl_pmu_exit(void)
{
	perf_pmu_unregister(&resctrl_pmu);
	pr_info("Unregistered resctrl PMU\n");
}