# Cover Letter

Subject: [PATCH 0/8] resctrl: Add perf PMU for resctrl monitoring

Expose resctrl monitoring data via a lightweight perf PMU so userspace
and eBPF can access metrics through perf_event_open() instead of polling
kernfs files. This eliminates the global rdtgroup_mutex in the read path.

Background: The kernel’s initial cache-monitoring interface shipped via 
perf (commit 4afbb24ce5e7, 2015). That approach tied monitoring to tasks
and cgroups. Later, cache control was designed around the resctrl 
filesystem to better match hardware semantics, and the incompatible perf 
CQM code was removed (commit c39a0e2c8850, 2017). This series implements
a thin, generic perf PMU that is compatible with resctrl.

Design: The "resctrl" PMU is a small adapter on top of resctrl’s 
monitoring path:
- Event selection uses `attr.config` to pass an open `mon_data` fd
  (e.g. `mon_L3_00/llc_occupancy`).
- Events must be CPU-bound within the file's domain.
- Event init resolves and pins the rdtgroup, prepares struct rmid_read via
  mon_event_setup_read(), and validates the bound CPU is in the file's 
  domain CPU mask.
- Reads run on the current CPU via `mon_event_read_this_cpu()` without IPI.
  Perf ensures the read executes on the bound CPU.
- Sampling is not supported; reads match the `mon_data` file contents.
- If the rdtgroup is deleted, reads return 0.

Includes a new selftest (tools/testing/selftests/resctrl/pmu_test.c)
to validate the PMU event init path. Adds PMU testing to existing CMT tests.

Example usage (see Documentation/filesystems/resctrl.rst):
Open a monitoring file and pass its fd in `perf_event_attr.config`, with
`attr.type` set to the `resctrl` PMU type.
