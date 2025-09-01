# Kernel Make Automation and Fast Build Techniques

## Overview

This document covers automated kernel testing infrastructure and techniques for fast kernel builds, based on research into modern kernel development workflows and CI/CD systems.

## Intel 0-Day CI System

### What is 0-Day CI?

Intel's 0-Day CI is an automated Linux kernel test service that provides comprehensive test coverage of the Linux kernel. It's designed for "shift-left" testing, catching issues as early as possible in the development process.

**Key Features:**
- **Automated regression testing** that intercepts kernel development at its earliest stages
- **Comprehensive coverage**: kernel build, static analysis, boot, functional, performance and power tests
- **Available to the worldwide Linux kernel community**
- **Tests beyond upstream**: Also tests developers' and maintainers' trees to catch issues earlier

### Performance and Speed

The 0-Day CI system is remarkably fast:
- **Build times**: Standard defconfig builds average around 9 minutes
- **Complete testing**: The full pipeline (build + boot + functional + performance tests) typically completes within 10-15 minutes
- **Scale**: Tests 50+ performance benchmarks across multiple hardware platforms

### How It Works

1. **Automatic patch interception**: Monitors kernel mailing lists and git trees
2. **Multi-stage testing pipeline**:
   - Static analysis using industry-standard tools
   - Cross-architecture builds
   - Boot tests on various platforms (Intel architecture labs)
   - Functional testing
   - Performance regression detection
   - Automated bisection when tests fail

### Performance Testing Results

Example performance monitoring results from recent kernel cycles:
- **v5.0 cycle**: Reported 14 major performance regressions and 5 improvements
- **v5.3 cycle**: Reported 21 major performance regressions and 6 improvements  
- **Continuous monitoring**: Uses 50+ benchmarks including hackbench, fio, unixbench, netperf

## Other Kernel CI Systems

### Linux Foundation CI Infrastructure

- **CIP (Civil Infrastructure Platform) CI**: Monitors CIP Kernel branches and upstream stable release candidates
- **GitLab CI/CD integration**: Provides binaries for multiple kernel configurations
- **LAVA testing framework**: For hardware-in-the-loop testing
- **Multiple architectures**: ARM, x86, RISC-V, and others

### GPU/DRM Testing

- **GitLab.freedesktop.org**: Automated testing for Mesa and DRM subsystems
- **Hardware-specific testing**: Real hardware testing for graphics drivers

### kbuild Test Robot

The kbuild test robot (part of 0-Day infrastructure):
- **Compiler coverage**: Tests with both GCC and Clang
- **Static analysis**: Reports compilation errors, warnings, and static analysis issues
- **Automatic reporting**: Emails patch authors with detailed reproduction steps
- **Format**: `Reported-by: kbuild test robot <lkp@intel.com>`

## Fast Kernel Build Techniques

### 1. Parallel Compilation (`make -j`)

**Basic usage:**
```bash
make -j$(nproc)  # Use all available CPU cores
make -j16        # Use specific number of jobs
```

**Best practices:**
- Use number of jobs = CPU cores + 1 or 2
- Ensure sufficient RAM (minimum 16GB recommended for kernel development)
- The kernel Makefile has correct dependencies, making parallel builds safe

### 2. ccache (Compiler Cache)

**Installation and setup:**
```bash
# Install ccache
sudo apt install ccache  # Ubuntu/Debian
sudo yum install ccache   # RHEL/CentOS

# Configure kernel build to use ccache
export CC="ccache gcc"
# or for Clang:
export CC="ccache clang"

# Set build timestamp to avoid cache misses
export KBUILD_BUILD_TIMESTAMP=""
```

**Performance improvements:**
- **First build**: Slower as cache is populated
- **Subsequent builds**: 8X speedup typically achieved
- **Cache hit rates**: ~32% direct cache hits are common
- **Best for**: Iterative development where most code remains unchanged

**Configuration tips:**
- Unset `CONFIG_GCC_PLUGINS` to avoid cache misses
- Place ccache directory on SSD for better performance

### 3. distcc (Distributed Compilation)

**Requirements:**
- All nodes must have the same GCC version
- Nodes don't need identical environments
- Source code must compile with `make -j` (which kernel does)

**Setup example:**
```bash
# On build farm nodes
export CC="distcc gcc"
export DISTCC_HOSTS="192.168.1.10 192.168.1.11 192.168.1.12"

# Build with distributed compilation
make -j12  # Adjust based on total cores across all nodes
```

**Performance results:**
- **3 identical machines**: 2.5-2.8X faster than local compilation
- **16 machines**: Over 10X speedup reported
- **Real-world example**: Linux kernel 4.19.7 on 3-node ARM build farm:
  - Single node: 44 minutes
  - Distributed: 24 minutes

### 4. Combined Techniques

**ccache + distcc:**
```bash
export CC="ccache distcc gcc"
```

Benefits:
- First distributed build populates ccache across nodes
- Subsequent builds benefit from both distributed compilation and caching
- Ideal for CI/CD environments with build farms

### 5. Hardware Optimizations

**RAM requirements:**
- **Minimum**: 8GB (will cause swapping during parallel builds)
- **Recommended**: 16GB for kernel development
- **Optimal**: 32GB+ for large parallel builds with ccache

**Storage:**
- **SSD strongly recommended**: Dramatically reduces I/O bottlenecks
- **NVMe preferred**: For ccache directory and build output
- **Separate drives**: Consider separate drives for source, build output, and ccache

### 6. Advanced Kernel Configuration Optimization

#### CONFIG_TRIM_UNUSED_KSYMS Build Time Improvements

**CONFIG_TRIM_UNUSED_KSYMS** provides significant build time and size optimizations:

**Benefits:**
- **9-29% compilation time reduction** by trimming unused exported kernel symbols
- **Binary size reduction**, especially effective with Link-Time Optimization (LTO)  
- **Security improvements** by reducing attack surface
- **Build time cost now negligible** (improved significantly in 2021)

**How it works:**
- Gathers required symbols from configured modules
- Stores symbols in `include/generated/autoksyms.h` as defines
- Controls activation of corresponding `EXPORT_SYMBOL()` instances
- Rebuilds affected files until symbol list becomes stable

**Implementation:**
```bash
# Enable in kernel config
CONFIG_TRIM_UNUSED_KSYMS=y

# Optional: Create symbol whitelist for out-of-tree modules
echo "my_exported_symbol" >> symbol_whitelist.txt
echo "another_symbol" >> symbol_whitelist.txt
```

#### Strategic Configuration for Build Speed

**Minimal configurations:**
```bash
# Fastest build: 9x faster than defconfig (31s vs 4m43s)
make tinyconfig
# Results in ~22x smaller image (581K vs 13M)

# Hardware-specific minimal config
make localmodconfig  # Only modules for currently loaded hardware
# Reduces module count from ~7000 to ~200

# Use after loading all intended hardware modules:
modprobe <all-needed-modules>
make localmodconfig
```

**Performance-focused configuration options:**
```bash
# Disable debug features for faster compilation
CONFIG_DEBUG_INFO=n
CONFIG_DEBUG_KERNEL=n

# Optimize for size (faster compilation)
CONFIG_CC_OPTIMIZE_FOR_SIZE=y

# Remove unnecessary subsystems for headless builds
CONFIG_SOUND=n
CONFIG_DRM=n

# Enable module support for hot-swapping during development
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
```

**NixOS derpconfig approach:**
```bash
# Start from minimal base
make ARCH=x86_64 allnoconfig

# Use tinyconfig as baseline
make tinyconfig

# Apply localmodconfig for hardware support
make localmodconfig

# Convert error messages to required modules
# (iterative process based on missing functionality)
```

#### Development-Focused Configurations

**Out-of-tree module development:**
```bash
# Build only specific subsystem
make fs/resctrl/

# Build specific module directory  
make M=fs/resctrl

# Build external module
make M=/path/to/external/module
```

**Fast incremental development:**
```bash
# Use git worktrees to avoid recompilation when switching branches
git worktree add ../kernel-feature-branch feature-branch
cd ../kernel-feature-branch
# Build once, then switch without rebuilding base

# Parallel module building
make -j$(nproc) modules
make -j$(nproc) modules_install
```

**Debug-optimized builds:**
```bash
# Fast debug builds with reasonable optimization
CONFIG_DEBUG_EXPERIENCE=y  # Uses -Og flag
# Only 6% slower than production builds

# Disable expensive debug features
CONFIG_DEBUG_PAGEALLOC=n
CONFIG_DEBUG_SLUB=n
CONFIG_LOCKDEP=n
```

### 7. Modern Linker Optimizations

#### mold Linker (2024 Status)

**mold** is a modern linker that delivers exceptional performance improvements:

**Performance benchmarks:**
- **MySQL 8.3**: 10.84s → 0.46s (23x speedup)
- **Clang 19**: 42.07s → 1.35s (31x speedup)  
- **General performance**: 20-30x faster than GNU ld, 3-8x faster than LLVM lld

**Implementation (userspace only):**
```bash
# For GCC 12.1+ and Clang (userspace programs only)
export LDFLAGS="-fuse-ld=mold"
make CC=gcc LDFLAGS="-fuse-ld=mold"

# Alternative: intercept all linker calls (userspace only)
mold -run make -j$(nproc)

# CANNOT be used for kernel builds:
# make LLVM=1 LDFLAGS="-fuse-ld=mold"  # This will fail
```

**Platform support:**
- x86-64, i386, ARM64, ARM32, RISC-V (64/32-bit)
- PowerPC (32-bit, 64-bit big/little endian)
- s390x, LoongArch, SPARC64, m68k, SH-4

**Kernel status (2024):**
- **Cannot currently build Linux kernels** due to limited linker script support
- Mold supports only basic linker script features (sufficient for libc.so reading)
- Linux kernel requires complex linker scripts that mold doesn't support
- Kernel/embedded programming support actively being developed as a priority
- Current users must use lld or GNU ld for kernel builds

**Future outlook:**
- Rui Ueyama (mold creator) prioritizes kernel/embedded support as "one of the last grounds to tackle"
- Development philosophy: replace complex linker scripts with simpler mechanisms
- GitHub Issue #563 tracks kernel support development
- No ETA provided, but active experimentation ongoing

#### LLVM lld Linker

**lld** remains the preferred choice for kernel builds:

**Benefits:**
- 2-4x faster than GNU gold linker
- Lower memory usage than GNU ld
- Full kernel build support with LLVM toolchain
- Supports Link-Time Optimization (LTO)

**Implementation:**
```bash
# For kernel builds with LLVM
make CC=clang LD=ld.lld

# With full LLVM toolchain
make LLVM=1
```

**Recent improvements (2024):**
- Performance optimizations in lld 16.0+
- Used by default in Rust compilation (7x linking speedup)
- 40% reduction in end-to-end compilation times

#### GNU gold vs GNU ld

**GNU gold status:**
- 3-4x faster than GNU ld when multithreaded
- **Deprecated** as of GNU Binutils 2.44 (unmaintained)
- Should be avoided for new projects

**GNU ld baseline:**
- Default linker, slowest performance
- Still widely used but being replaced

### 8. CI/CD Integration

**Docker-based builds:**
- Pre-built containers with toolchains and ccache
- Consistent build environments
- Fast container startup vs VM overhead

**Build farm strategies:**
- Dedicated build nodes with high core counts
- Shared ccache storage (NFS or distributed filesystems)
- Automated build triggering from git hooks

## GitHub Actions CI/CD Optimization

### GitHub Actions Runner Improvements (2024)

GitHub significantly upgraded standard runners in 2024:
- **Standard runners**: 4 vCPUs (up from 2), 16GB RAM, 14GB disk space
- **Large runners**: Scale up to 96 vCPUs with 384GB RAM
- **Cost structure**: $0.008/min for standard, up to $0.192/min for 96-core

**Memory optimization strategies:**
```yaml
- name: Maximize build space
  uses: easimon/maximize-build-space@v10
  with:
    root-reserve-mb: 512
    swap-size-mb: 1024
    remove-dotnet: 'true'
    remove-android: 'true'
    remove-haskell: 'true'
    remove-codeql: 'true'
```

### Real-world Kernel CI Projects

Several mature projects demonstrate effective kernel CI/CD:

**Android kernel projects:**
- **dabao1955/kernel_build_action**: Supports multiple toolchains (AOSP GCC, AOSP Clang, Proton Clang)
- **KernelSU**: Over 5,000 workflow runs demonstrating high-volume builds
- **xiaocenter/KernelSU_Action**: Reports 2/5 build time reduction with caching

**Hardware-specific projects:**
- **Raspberry Pi Linux**: 1,741+ continuous integration tests
- **analogdevicesinc/linux**: Embedded Linux with sophisticated matrix builds

### ccache GitHub Actions Integration

**Optimal ccache configuration:**
```yaml
- name: Setup ccache
  uses: hendrikmuhs/ccache-action@v1.2
  with:
    key: ${{ runner.os }}-ccache-${{ matrix.config }}-${{ github.sha }}
    restore-keys: |
      ${{ runner.os }}-ccache-${{ matrix.config }}-
      ${{ runner.os }}-ccache-
    max-size: 8G

- name: Configure ccache for kernel
  run: |
    echo "KBUILD_BUILD_TIMESTAMP=" >> $GITHUB_ENV
    echo "CCACHE_COMPRESS=true" >> $GITHUB_ENV
    echo "CCACHE_COMPRESSLEVEL=6" >> $GITHUB_ENV
```

**Performance results:**
- Cold cache: 735.22s (13.62% slower initially)
- Hot cache: **98.9s vs 647.07s baseline** (6.54x speedup)
- Cache hit rates: 99.7% for incremental builds

### Workflow Optimization Strategies

**Matrix builds for parallel compilation:**
```yaml
strategy:
  matrix:
    include:
      - config: defconfig
        arch: x86_64
      - config: allmodconfig  
        arch: x86_64
      - config: tinyconfig
        arch: x86_64
```

**Conditional compilation:**
```yaml
- name: Check for kernel changes
  uses: dorny/paths-filter@v2
  id: changes
  with:
    filters: |
      kernel:
        - 'arch/**'
        - 'kernel/**'
        - 'drivers/**'
        - 'fs/**'
```

**Artifact management:**
```yaml
- name: Upload kernel artifacts
  uses: actions/upload-artifact@v4
  with:
    name: kernel-${{ matrix.config }}-${{ github.sha }}
    path: |
      arch/*/boot/bzImage
      System.map
      .config
    retention-days: 7
```

### Cloud-Based and Self-Hosted Infrastructure

#### AWS Spot Instance Integration

**Cost-effective scaling with spot instances:**
- **Up to 90% cost reduction** compared to on-demand instances
- Use `c5.4xlarge` (16 vCPUs) or `c5.9xlarge` (36 vCPUs) for kernel builds
- Implement spot instance interruption handling

```yaml
# Example spot instance configuration
- name: Launch spot instance for build
  run: |
    aws ec2 request-spot-instances \
      --spot-price "0.50" \
      --launch-specification '{
        "ImageId": "ami-0abcdef1234567890",
        "InstanceType": "c5.4xlarge",
        "SecurityGroupIds": ["sg-12345678"],
        "UserData": "#!/bin/bash\n# Setup build environment"
      }'
```

#### Self-Hosted Runner Performance

**3-node ARM64 build farm example:**
- **Single node**: 66 minutes (baseline)
- **Distributed with distcc**: 24 minutes (63% improvement)
- **16-core ARM64 nodes** with shared ccache storage

**Hardware recommendations for self-hosted runners:**
- **CPU**: 16+ cores (AMD Ryzen 9, Intel Core i9, or ARM64 equivalents)
- **RAM**: 64GB minimum (128GB optimal for allmodconfig builds)
- **Storage**: NVMe SSD 1TB+ for builds, separate drive for ccache
- **Network**: 10GbE for shared ccache/distcc

#### Kubernetes-Based Auto-Scaling

**Actions Runner Controller (ARC) setup:**
```yaml
# Example ARC deployment
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: kernel-build-runners
spec:
  template:
    spec:
      resources:
        limits:
          cpu: "16"
          memory: "64Gi"
        requests:
          cpu: "8" 
          memory: "32Gi"
      nodeSelector:
        node-type: compute-optimized
```

**Benefits:**
- **Auto-scaling** based on build queue depth
- **Cost optimization** through pod scheduling
- **Resource isolation** for different build types
- **Integration with spot nodes** for further cost reduction

#### Custom Docker Build Environments

**Specialized kernel build containers:**
```dockerfile
# Example optimized kernel build container
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential \
    ccache \
    clang \
    lld \
    mold \
    bc \
    kmod \
    cpio \
    flex \
    bison \
    libelf-dev \
    libssl-dev

# Pre-configure ccache
ENV CCACHE_DIR=/cache
ENV CCACHE_MAXSIZE=8G
ENV CCACHE_COMPRESS=true
ENV CCACHE_COMPRESSLEVEL=6

# Use mold linker by default
ENV LDFLAGS="-fuse-ld=mold"
```

**Container registry examples:**
- **a13xp0p0v/kernel-build-containers**: Multi-compiler support (GCC 4.9-14, Clang 5-17)
- **Multiple architectures**: x86_64, ARM64, RISC-V support
- **Ubuntu versions**: 16.04 through 24.04 base images

## Comprehensive Workflow Optimization Strategy

### Layered Performance Approach

**Tier 1 - Foundation (Must-Have):**
1. **ccache with proper configuration** (6.54x speedup for incremental builds)
2. **Parallel compilation** with `make -j$(nproc)` 
3. **Modern linker** (lld for kernel builds, mold NOT supported for kernels)
4. **Strategic kernel configuration** (localmodconfig, CONFIG_TRIM_UNUSED_KSYMS)

**Tier 2 - Advanced Optimizations:**
1. **GitHub Actions optimization** (4 vCPU runners, proper caching)
2. **Container-based builds** with pre-configured environments
3. **Matrix builds** for parallel architecture/configuration testing
4. **Conditional compilation** based on file changes

**Tier 3 - Infrastructure Scaling:**
1. **Self-hosted runners** for high-volume builds
2. **Cloud integration** with spot instances (90% cost reduction)
3. **Kubernetes auto-scaling** with ARC
4. **Distributed compilation** with distcc for build farms

### Implementation Timeline

**Week 1 - Quick Wins:**
- Enable ccache with `KBUILD_BUILD_TIMESTAMP=""`
- Configure GitHub Actions with hendrikmuhs/ccache-action
- Switch to lld linker for kernel builds
- Enable CONFIG_TRIM_UNUSED_KSYMS

**Week 2 - Advanced Setup:**
- Implement matrix builds and conditional compilation
- Create optimized Docker containers
- Set up artifact management and retention policies
- Configure build parallelization strategies

**Week 3+ - Infrastructure:**
- Deploy self-hosted runners if volume justifies
- Implement cloud scaling with spot instances
- Set up distributed compilation for team environments
- Optimize for specific workload patterns

### Cost-Benefit Analysis

**GitHub Actions Standard Runners:**
- **Cost**: $0.008/min ($0.48/hour)
- **Performance**: 4 vCPU, 16GB RAM
- **Best for**: Small teams, occasional builds

**GitHub Actions Large Runners:**
- **Cost**: $0.192/min for 96-core ($11.52/hour)  
- **Performance**: Up to 96 vCPU, 384GB RAM
- **Best for**: Critical builds, high-frequency CI/CD

**Self-Hosted Infrastructure:**
- **Initial cost**: $3,000-5,000 per 16-core node
- **Operating cost**: $100-200/month per node
- **Break-even**: ~500 build hours/month vs GitHub runners
- **Best for**: High-volume development teams

### Performance Benchmarks Summary

**Build time improvements by technique:**
- **ccache (hot cache)**: 6.54x speedup
- **mold linker**: 20-30x faster linking
- **tinyconfig**: 9x faster than defconfig
- **CONFIG_TRIM_UNUSED_KSYMS**: 9-29% compilation speedup
- **localmodconfig**: ~35x reduction in modules (7000→200)
- **Distributed compilation**: 63% improvement (3-node farm)

## Key Takeaways for Fast Development

1. **Start with hardware**: Sufficient RAM and SSD storage are fundamental
2. **Implement ccache first**: Essential 6.54x speedup for iterative development
3. **Use modern linkers**: lld for kernels (mold not supported), mold for userspace (20x+ speedup)
4. **Optimize configurations**: CONFIG_TRIM_UNUSED_KSYMS and localmodconfig
5. **Leverage GitHub Actions**: Modern 4 vCPU runners with proper caching
6. **Scale intelligently**: Self-hosted runners for high-volume, spot instances for cost
7. **Monitor performance**: Use 0-Day CI insights and continuous benchmarking
8. **Iterate systematically**: Layer optimizations from foundation to advanced scaling

## References

### Original Research Sources
- Intel 0-Day CI Performance Reports (v5.1, v5.3, v5.11, etc.)
- Linux Kernel Performance Testing (LKP) - Intel GitHub repository
- Kernel Testing Guide - Linux Kernel Documentation
- ccache documentation and performance analysis
- distcc distributed compilation system documentation

### Additional Sources (2024-2025)
- **mold linker**: rui314/mold GitHub repository and performance benchmarks
- **LLVM lld**: Official LLVM linker documentation and Rust integration studies
- **CONFIG_TRIM_UNUSED_KSYMS**: Linux kernel LKML patches and Gentoo LTO project
- **Kernel build containers**: a13xp0p0v/kernel-build-containers project
- **GitHub Actions**: Official GitHub documentation and hendrikmuhs/ccache-action
- **Kubernetes ARC**: Actions Runner Controller documentation and deployment guides
- **AWS Spot Integration**: EC2 documentation and cost optimization studies

### Real-World Project Examples
- **Android kernel CI**: dabao1955/kernel_build_action, KernelSU projects
- **Hardware-specific builds**: Raspberry Pi Linux, analogdevicesinc/linux
- **Embedded systems**: zen-kernel, NixOS derpconfig project
- **Performance benchmarking**: Phoronix Test Suite kernel build benchmarks

The combination of these modern techniques enables kernel developers to achieve build and test cycles comparable to the professional CI/CD systems used by major kernel contributors, with builds optimized from 30+ minutes down to 5-10 minutes for development iterations.