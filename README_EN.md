# LanZhouKPM

An Android kernel-protection KPM module built on [KPatch-Next](https://github.com/KernelSU-Next/KPatch-Next) (an independent implementation of [KernelPatch](https://github.com/bmax121/KernelPatch)). Free and open source (module source code).

> **Warning**: This module works by hooking kernel functions — kernel-level operations. Improper use may cause freezes, panics, or even system damage. Use it only if you understand how it works, **at your own risk**.

## Features

- **Main protection (block device protection)**
  - When active, processes outside the whitelist cannot open block devices (`blkdev_open` / `blkdev_get` / `blkdev_get_by_dev`), blocking malicious writes to partitions at the source.
  - The whitelist identifies system processes (init / ueventd / vold / kworker, etc.) using three anchors: process name + UID + executable path.
  - `blkdev_write_iter` / `blkdev_ioctl` are observed with rate-limited logging only (observed, not blocked).
  - A 5-second drain period follows activation; new opens are only blocked after it.
- **Kernel module protection**: loading kernel modules is blocked while protection is active.
- **Process protection**: blocks `kill` / `tkill` / `tgkill` against protected processes.
- **Extra protection — adb directory protection**: blocks creating files and directories under `/data/adb`, preventing malicious modules from landing.
- **Anti-unload**: without unlocking, `find_module` returns nothing and `delete_module` is denied. You must unlock before unloading, otherwise the kernel panics — **by design**.
- **Safe degradation**: if identity anchors (`__get_task_comm`, exe path, etc.) are missing, the module automatically enters narrow mode and installs only the anti-unload hook, avoiding damage to baseband/system processes.
- **Reboots are never affected**: this version does not hook `reboot`; you can always reboot normally.

## Control Protocol

| Command | Purpose |
| --- | --- |
| `S` | Query status; returns `1,<block_count>[,D]` (D = degraded mode) |
| `V:Q` | Query version; returns `A` |
| `F:Q` | Query the list of hooks that failed to install |
| `VT:` | Enable main protection |
| `VD:` | Disable main protection |
| `VU:` | Unlock a 10-second unload window |
| `M:1` / `M:0` / `M:Q` | Enable / disable / query extra protection |
| `A:Q` / `A:R` | Query / clear extra-protection alerts |

## Open-Source Scope

- This repository open-sources **the KPM module source code only**.
- The official console (including A/B variants and the self-extracting script) is **not open source**.
- For security reasons, some non-core content (tokens, keys, etc.) is not included in this source code.

## Compatibility

- Your root manager (except APatch and similar, because APatch ships its own KernelPatch which conflicts with KPatch-Next!!) + KPatch-Next (0.13.x)
- arm64 Android, kernel 5.x / 6.x

## Building

Requirements: NDK (r29 verified), and the KPM SDK headers from the KernelPatch or KPatch-Next repository (`kernel/` directory — remember to initialize the `linux` submodule).

Windows example (`build.cmd`):

```bat
@echo off
set NDK=D:\Android\Sdk\ndk\29.0.14206865
set CC=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android31-clang
set STRIP=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe
set KP=E:\KPatch-Next\kernel

set INC=-I%KP% -I%KP%\include -I%KP%\patch\include -I%KP%\linux\include -I%KP%\linux\arch\arm64\include -I%KP%\linux\tools\arch\arm64\include
set DEFS=-D__KERNEL__ -D__LINUX__ -D__USE_MISC -D_GNU_SOURCE -D__LINUX_ARM_ARCH__=8 -D__aarch64__ -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-semantic-interposition -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden -nostdinc -ffreestanding

"%CC%" -iquote . %INC% %DEFS% -Wall -O2 -c -o module.o LANZHOUKPM-1.0.c || exit /b 1
"%CC%" -nostdlib -r -o LANZHOUKPM.kpm module.o || exit /b 1
"%STRIP%" -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack LANZHOUKPM.kpm
echo ALL-OK
```

The output `LANZHOUKPM.kpm` is the KPM module.

## Usage

1. Load `LANZHOUKPM.kpm` via the KPatch-Next WebUI, or load it with the `kpatch` command.
2. Enable/disable protection through the official console (closed source) or by sending commands per the control protocol above.
3. **You must send `VU:` before unloading**, then unload within the 10-second window; otherwise the kernel panics.
4. Module logs appear in dmesg with the `[bd]` prefix (`[+] KP I [bd] ...` / `[-] KP E [bd] ...`).

## FAQ

- **Cannot write to partitions / flash after enabling protection**: disable protection first (`VD:`).
- **A hook shows as failed**: check with `F:Q`; `blkdev-get` failing on certain kernels is normal.
- **Status shows degraded**: the device kernel is missing identity-anchor symbols; only the anti-unload ability remains and main protection does not take effect.

## Disclaimer

This module involves kernel-level hooking. The author is not responsible for any device damage or data loss caused by using this module. Back up your data before use.

## Credits

- [KernelPatch](https://github.com/bmax121/KernelPatch) (bmax121) — kernel patching and hooking framework
- [KPatch-Next](https://github.com/KernelSU-Next/KPatch-Next) (KernelSU-Next) — KPM support

QQ users:
   是奶不是瓶
   CNYiJieqwq异界
   御坂114514号
   Aaa .z.
   心怡
And one friend who prefers to remain anonymous

Author: Lanzhou · Channel: [@LANZHOUKPM](https://t.me/LANZHOUKPM)

## License

[GPL-2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
