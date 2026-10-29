#!/usr/bin/env bash
# Print a machines.md entry for this host (paste into docs/machines.md).
h=$(hostname); grep -qiE "microsoft|wsl" /proc/sys/kernel/osrelease 2>/dev/null && h="$h-wsl2"
gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "n/a (VM/WSL2: set Windows power mode to Best performance)")
turbo=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null || echo "n/a")
wolf=$(grep -h "LIBWOLFSSL_VERSION_STRING" "${WOLFSSL_PREFIX:-$HOME/pqc/install/wolfssl-5.6.3}/include/wolfssl/version.h" 2>/dev/null | awk '{print $3}')
cat <<MD
## $h  ($(date +%F))
- CPU: $(lscpu | sed -n 's/^Model name: *//p') — $(nproc) logical CPUs
- Kernel: $(uname -srm)
- OS: $(. /etc/os-release; echo "$PRETTY_NAME")
- Virtualization: $(systemd-detect-virt 2>/dev/null || echo unknown)
- Governor: $gov
- Turbo/boost flag: $turbo
- gcc: $(gcc -dumpfullversion 2>/dev/null)
- wolfSSL: ${wolf:-not built}
MD
