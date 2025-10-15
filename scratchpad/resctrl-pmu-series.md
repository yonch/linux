# Cover Letter

Subject: [PATCH 0/8] resctrl: Add perf PMU for resctrl monitoring

Expose resctrl monitoring data via a lightweight perf PMU. 

Background: The kernel’s initial cache-monitoring interface shipped via 
perf (commit 4afbb24ce5e7, 2015). That approach tied monitoring to tasks
and cgroups. Later, cache control was designed around the resctrl 
filesystem to better match hardware semantics, and the incompatible perf 
CQM code was removed (commit c39a0e2c8850, 2017). This series implements
a thin, generic perf PMU that _is_ compatible with resctrl.

Motivation: perf support enables measuring cache occupancy and memory 
bandwidth metrics on hrtimer (high resolution timer) interrupts via eBPF.
Compared with polling from userspace, hrtimer-based reads remove 
scheduling jitter and context switch overhead. Further, PMU reads can be 
parallel, since the PMU read path need not lock resctrl's rdtgroup_mutex.
Parallelization and reduced jitter enable more accurate snapshots of
cache occupancy and memory bandwidth. [1] has more details on the 
motivation and design.

Design: The "resctrl" PMU is a small adapter on top of resctrl’s 
monitoring path:
- Event selection uses `attr.config` to pass an open `mon_data` fd
  (e.g. `mon_L3_00/llc_occupancy`).
- Events must be CPU-bound within the file's domain. Perf is responsible 
  the read executes on the bound CPU.
- Event init resolves and pins the rdtgroup, prepares struct rmid_read via
  mon_event_setup_read(), and validates the bound CPU is in the file's 
  domain CPU mask.
- Sampling is not supported; reads match the `mon_data` file contents.
- If the rdtgroup is deleted, reads return 0.

Includes a new selftest (tools/testing/selftests/resctrl/pmu_test.c)
to validate the PMU event init path, and adds PMU testing to existing 
CMT tests.

Example usage (see Documentation/filesystems/resctrl.rst):
Open a monitoring file and pass its fd in `perf_event_attr.config`, with
`attr.type` set to the `resctrl` PMU type.

The patches are based on top of v6.18-rc1 (commit 3a8660878839).

[1] https://www.youtube.com/watch?v=4BGhAMJdZTc
