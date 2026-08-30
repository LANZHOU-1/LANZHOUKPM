# LanZhouKPM

基于 [KPatch-Next](https://github.com/KernelSU-Next/KPatch-Next)（[KernelPatch](https://github.com/bmax121/KernelPatch) 的独立实现）的 Android 内核防护 KPM 模块。免费、开源（模块源码）。

> **警告**：本模块通过内核 hook 工作，属于内核级操作。使用不当可能导致死机、panic 甚至系统异常。请在了解原理的前提下使用，**风险自担**。

## 功能

- **主防护（块设备防护）**
  - 防护开启后，白名单之外的进程无法打开块设备（`blkdev_open` / `blkdev_get` / `blkdev_get_by_dev`），从源头阻止对分区的恶意写入。
  - 白名单基于进程名 + UID + 可执行文件路径三重锚点识别系统进程（init / ueventd / vold / kworker 等）。
  - 对 `blkdev_write_iter` / `blkdev_ioctl` 做限速观察记录（只观测，不拦截）。
  - 激活后有 5 秒排水期，之后才对新打开生效。
- **内核模块防护**：防护开启期间禁止加载内核模块。
- **进程防护**：拦截对受保护进程的 `kill` / `tkill` / `tgkill`。
- **附加防护  adb 目录防护**：禁止在 `/data/adb` 下创建文件与目录，阻止恶意模块落地。
- **防卸载**：未解锁时 `find_module` 返回空、`delete_module` 被拒绝。卸载前必须先解锁，否则触发内核 panic——这是**有意设计**。
- **安全降级**：身份锚点（`__get_task_comm`、exe 路径等）缺失时自动进入窄模式，只安装防卸载 hook，避免误伤基带/系统进程。


## 控制协议

| 命令 | 作用 |
| --- | --- |
| `S` | 查询状态，返回 `1,<拦截次数>[,D]`（D = 降级模式） |
| `V:Q` | 查询版本，返回 `A` |
| `F:Q` | 查询 hook 安装失败列表 |
| `VT:` | 开启主防护 |
| `VD:` | 关闭主防护 |
| `VU:` | 解锁 10 秒卸载窗口 |
| `M:1` / `M:0` / `M:Q` | 开启 / 关闭 / 查询附加防护 |
| `A:Q` / `A:R` | 查询 / 清除附加防护告警 |

## 开源范围

- 本仓库仅开源 **KPM 模块源码**。
- 官方控制台（含 A/B 版本、自解压脚本）**未开源**。
- 出于安全性考虑，此源码未包含部分非核心内容（token、密钥等）。

## 兼容性

- 您的root管理器（除了apatch等 因为他自带KP的会与KPatch-Next冲突！！） + KPatch-Next（0.13.x）
- arm64 Android，内核 5.x / 6.x 

## 编译

需要：NDK（r29 实测可用）、KernelPatch 或 KPatch-Next 仓库的 KPM SDK 头文件（`kernel/` 目录，注意初始化 `linux` 子模块）。

Windows 示例（`build.cmd`）：

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

产物 `LANZHOUKPM.kpm` 即 KPM 模块。

## 使用

1. 在 KPatch-Next WebUI 选择 `LANZHOUKPM.kpm` 加载，或用 `kpatch` 命令加载。
2. 通过官方控制台（闭源）或自行按上述控制协议发送命令开关防护。
3. **卸载前必须先发 `VU:`**，在 10 秒窗口内卸载；否则panic。
4. 模块日志在 dmesg 中，前缀 `[bd]`（`[+] KP I [bd] ...` / `[-] KP E [bd] ...`）。

## 常见问题

- **开防护后无法写分区 / 刷机**：先关闭防护（`VD:`）。
- **某 hook 显示失败**：用 `F:Q` 查看；`blkdev-get` 在 某些内核失败是正常的。
- **状态显示降级**：设备内核缺少身份锚点符号，主防护不生效。

## 免责声明

本模块涉及内核级 hook，作者不对任何因使用本模块造成的设备损坏、数据丢失负责。请备份数据后使用。

## 鸣谢

- [KernelPatch](https://github.com/bmax121/KernelPatch)（bmax121）—— 内核补丁与 hook 框架
- [KPatch-Next](https://github.com/KernelSU-Next/KPatch-Next)（KernelSU-Next）—— KPM 支持

腾讯qq用户：
   是奶不是瓶
   CNYiJieqwq异界
   御坂114514号
   Aaa .z.
   心怡
还有1位不愿露面的朋友


作者：Lanzhou（蓝昼） · 更新频道：[@LANZHOUKPM](https://t.me/LANZHOUKPM)
