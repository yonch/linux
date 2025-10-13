# Cover Letter

Subject: [PATCH 0/8] resctrl: Add perf PMU for resctrl monitoring

  The resctrl filesystem exposes LLC occupancy and memory bandwidth
  metrics. Adding perf support allows users to measure and react to
  these metrics without context switch latency and cost associated
  with userspace polling (e.g., from eBPF).

  The kernel's initial interface for resctrl cache measurements was via
  perf, merged in commit 4afbb24ce5e7 — “perf/x86/intel: Add Intel Cache
  QoS Monitoring support” (Matt Fleming; committed by Ingo Molnar, Feb 
  25, 2015). That interface assumed cache measurements will be 
  transparently tied to tasks and cgroups, which did not happen. Instead,
  resctrl provided users more control over measured groups, and the perf
  interface, incompatible with resctrl, was removed in commit 
  c39a0e2c8850 — “x86/perf/cqm: Wipe out perf based cqm” (Vikas Shivappa;
  Aug 1, 2017). The removal patch noted multiple issues with the perf 
  interface, which are now resolved with resctrl.

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

  Patch list:
  1/8 resctrl: Pin rdtgroup in mon_data file lifetime
  2/8 resctrl/mon: Split RMID read init from execution
  3/8 resctrl/mon: Select cpumask before invoking mon_event_read()
  4/8 resctrl/mon: Create mon_event_setup_read() helper
  5/8 resctrl: Propagate CPU mask validation error via rr->err
  6/8 resctrl/pmu: Introduce skeleton PMU and selftests
  7/8 resctrl/pmu: Use mon_event_setup_read() and validate CPU
  8/8 resctrl/pmu: Implement .read via direct RMID read; add LLC selftest
