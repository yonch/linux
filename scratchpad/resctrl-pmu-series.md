# Cover Letter

Subject: [PATCH 0/8] resctrl: Add perf PMU for resctrl monitoring

  The resctrl filesystem exposes LLC occupancy and memory bandwidth
  metrics. Adding perf support allows users to measure and react to
  these metrics without context switch latency and cost associated
  with userspace polling (e.g., from eBPF).

  This series introduces a “resctrl” PMU that binds a perf event to a
  resctrl monitoring file. The series refactors monitoring code to
  separate setup and execution from kernfs handlers, pins the rdtgroup
  for the lifetime of an open mon_data file, and adds helpers to read
  on the current CPU (no IPI). 
  
  Later patches implement the PMU in stages:
  
   - Resolves the rdtgroup from the mon_data file
   - Extract resource, domain, and cpumask of event and check CPU
   - Implement .read path.

  Highlights:

  - Factor monitoring setup (domain lookup, rr init, cpumask selection)
  - Pin rdtgroup for mon_data file lifetime
  - Introduce a resctrl PMU and hook it into init/exit
  - Read directly for perf .read without rdtgroup_mutex
  - Add selftests for PMU setup, safety, and LLC occupancy

  Usage notes:

  - Pass a mon_data file descriptor in attr.config
  - Events must be CPU-bound; event_init validates the CPU belongs to
    the file’s domain mask

  Patch list:
  1/8 resctrl: Pin rdtgroup in mon_data file lifetime
  2/8 resctrl/mon: Split RMID read init from execution
  3/8 resctrl/mon: Select cpumask before invoking mon_event_read()
  4/8 resctrl/mon: Create mon_event_setup_read() helper
  5/8 resctrl: Propagate CPU mask validation error via rr->err
  6/8 resctrl/pmu: Introduce skeleton PMU and selftests
  7/8 resctrl/pmu: Use mon_event_setup_read() and validate CPU
  8/8 resctrl/pmu: Implement .read via direct RMID read; add LLC selftest

  Testing:

  - Selftests live under tools/testing/selftests/resctrl/
  - Run: make kselftest TARGETS=resctrl