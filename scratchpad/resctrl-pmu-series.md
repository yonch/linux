# Cover Letter

Subject: [PATCH 0/8] resctrl: Add perf PMU for resctrl monitoring

The resctrl filesystem exposes LLC occupancy and memory bandwidth metrics.
This series adds a read-only perf PMU named "resctrl" so userspace and eBPF
can read the same counters via perf_event_open(), avoiding userspace polling
of kernfs files and avoiding the global rdtgroup_mutex in the read path.

Background. The kernel’s initial cache-monitoring interface shipped via perf
as Intel CQM/MBM (4afbb24ce5e7, 2015). That approach tied monitoring to tasks
and cgroups. The subsystem was redesigned around the resctrl filesystem to
better match hardware semantics, and the perf CQM code was later removed
(c39a0e2c8850, 2017). Since then there’s been interest in a thin, generic
perf bridge for resctrl (e.g. proposals to add a "resctrl_pmu"). This series
implements that model for x86 resctrl monitors.

Design. The "resctrl" PMU is a small adapter on top of resctrl’s monitoring
path:
- Event selection uses `attr.config` to pass an open file descriptor of a
  resctrl `mon_data` file (e.g. "mon_L3_00/llc_occupancy").
- Events must be CPU-bound; the bound CPU must be valid for the file’s domain.
  Perf then ensures reads occur on that CPU.
- Event init resolves and pins the rdtgroup, prepares `struct rmid_read` via
  `mon_event_setup_read()`, and stores the valid CPU mask.
- Reads run on the current CPU via `mon_event_read_this_cpu()` with only
  `cpus_read_lock()`; no `rdtgroup_mutex` and no IPI.
- Sampling and exclude flags are not supported; values match the corresponding
  `mon_data` file at read time. If the rdtgroup is deleted, reads return 0.

Prerequisite refactoring in this series:
- Pin the rdtgroup for the lifetime of an open `mon_data` file and expose it to
  perf via `of->priv`.
- Split RMID read initialization from execution, and centralize domain lookup
  and CPU-mask selection in `mon_event_setup_read()`.
- Add a direct "read on this CPU" helper to avoid IPIs in the perf path.
- Propagate CPU-mask validation failures through `rr->err`.
- Document PMU usage and add selftests for safety and LLC occupancy.

Patch list:
  1/8 resctrl: Pin rdtgroup for mon_data file lifetime
  2/8 resctrl/mon: Split RMID read init from execution
  3/8 resctrl/mon: Select cpumask before invoking mon_event_read()
  4/8 resctrl/mon: Create mon_event_setup_read() helper
  5/8 resctrl: Propagate CPU mask validation error via rr->err
  6/8 resctrl/pmu: Introduce skeleton PMU and selftests
  7/8 resctrl/pmu: Use mon_event_setup_read() and validate CPU
  8/8 resctrl/pmu: Implement .read via direct RMID read; add LLC selftest

Example usage (see Documentation/filesystems/resctrl.rst):
- Open a monitoring file and pass its fd in `perf_event_attr.config`:
  `perf_event_open(&attr, -1, cpu, -1, 0)` where `attr.type` is the
  `resctrl` PMU type and `cpu` is in the file’s domain.
