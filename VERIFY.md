# PCLAutoPatch 2.99.0.0 验证记录

本文档记录 `pclautopatch` 在 PCL 2.99.0.0 上的完整验证过程与结果，
并附 2026-10-21 的独立复现记录。

- 概览与原理见 [README.md](README.md)。

---

## 0. 验证环境

| 项目 | 值 |
| --- | --- |
| 输入文件 | `E:\pxl-g\Plain Craft Launcher 2.exe` |
| 工具 | `E:\pxl-g\pclautopatch.exe` |
| 编译器 | MSYS2 UCRT64 g++ 16.2.0 (Rev3) |
| 编译选项 | `-std=c++17 -O2 -Wall -Wextra -static`（零警告） |
| 构建产物 | `pclautopatch.exe`，3,283,697 字节（2026-10-21 重建，含 `<filesystem>` 路径规范化） |
| 操作系统 | Windows（x64） |
| 首次验证日期 | 2026-10-20 |
| 复现验证日期 | 2026-10-21 |

> **历史路径说明**：2026-10-20 的原始记录中，工具位于 `E:\pxl-g\PCLAutoPatch\`，
> 且当时还存在 `E:\pxl-g\Plain Craft Launcher 2.patched.exe`（手工补丁版）
> 与 `E:\pxl-g\PCLPatch\`（手工补丁工具目录）。这三个路径在当前目录中**已不存在**，
> 工具已平铺到项目根目录。相关结论仍成立，因为手工补丁版的 SHA256 已被记录在案，
> 且 2026-10-21 的复现输出与之完全一致。

---

## 1. 输入文件（保持未修改）

```text
路径    E:\pxl-g\Plain Craft Launcher 2.exe
大小    5,980,160 字节 (0x5B4000)
SHA256  6B6E1260CB5A1D6A303855F1C60CAB3D0BC1AEBBA7E40A964180188B271E7386
```

验证流程结束后重新计算哈希，**与初始值一致**，确认输入文件未被修改。

---

## 2. PE 头

```text
e_lfanew        0x80
机器类型        0x014C (I386)
Optional Header 0xE0 字节 (PE32)
Section 数量    3
SectionAlignment 0x2000
FileAlignment    0x200
SizeOfImage      0x5B8000
```

| Section | VA | VirtualSize | RawPtr | RawSize | Characteristics |
| --- | --- | --- | --- | --- | --- |
| `.text` | `0x2000` | `0x581BD0` | `0x200` | `0x581C00` | `0x60000020` |
| `.rsrc` | `0x584000` | `0x31FB4` | `0x581E00` | `0x32000` | `0x40000040` |
| `.reloc` | `0x5B6000` | `0xC` | `0x5B3E00` | `0x200` | `0x42000040` |

`.reloc` 的 raw data 正好延伸到文件末尾（`0x5B3E00 + 0x200 = 0x5B4000`），
满足工具扩展该 section 的前提条件。

---

## 3. Metadata 概览

```text
TypeDef  665
MethodDef 6339
Field    3603
```

### 3.1 目标类型

| 类型 | token |
| --- | --- |
| `PCL.PageDownloadInstall` | `0x02000059` |
| `PCL.ModModpack` | `0x02000038` |
| `PCL.ModDownload` | `0x0200007E` |

### 3.2 目标方法

| 方法 | token | RVA | file off | 原始 code size |
| --- | --- | --- | --- | --- |
| `LoaderInit` | `0x06000513` | `0x0002DEB4` | `0x0002C0B4` | `0x5E` |
| `ModpackInstall(String,String,String)` | `0x060001F0` | `0x00012110` | `0x00010310` | `0x2EF` |

> `PCL.ModModpack` 中另有一个 0 参数的 `ModpackInstall` 提示桩。
> 工具用方法体大小（`0x2EF` / `0x380`）而非参数个数来区分二者。

### 3.3 目标字段

| 字段 | token | 所属类型 |
| --- | --- | --- |
| `DlClientListLoader` | `0x0400040F` | `PCL.ModDownload` |

### 3.4 `LoaderInit` 中提取 / 重建使用的 token

这些 token 全部从**原方法体的 IL 字节里**提取，而不是按名字猜测：

| 名称 | token | 提取位置（IL 偏移） |
| --- | --- | --- |
| `ControlInit` | `0x06000512` | `0x02` |
| `get_LoadMinecraft` | `0x06000607` | `0x09` |
| `get_PanLoad` | `0x06000605` | `0x0F` |
| `get_PanAllBack` | `0x06000551` | `0x15` |
| `_Lambda$__R3-4` | `0x0600061C` | `0x4D` |
| `Action::.ctor` | `0x0A00058D` | `0x52` |
| `PageLoaderInit` | `0x2B0000CA` | `0x59` |
| `DlClientListLoader`（字段） | `0x0400040F` | 按字段名解析 |

### 3.5 按名称解析的安装器 token

| 方法 | token |
| --- | --- |
| `InstallPackCurseForge` | `0x060001F4` |
| `InstallPackModrinth` | `0x060001F5` |
| `InstallPackHMCL` | `0x060001F6` |
| `InstallPackMMC` | `0x060001F7` |
| `InstallPackMCBBS` | `0x060001F8` |
| `InstallPackLauncherPack` | `0x060001F9` |
| `InstallPackCompress` | `0x060001FA` |

---

## 4. 原始 `LoaderInit` 方法体（0x5E 字节）

```text
IL_000: 02 28 12 05 00 06 02 02 6F 07 06 00 06 02 6F 05
IL_010: 06 00 06 02 6F 51 05 00 06 14 72 33 47 01 70 7E
IL_020: FB 09 00 04 2C 07 7E FB 09 00 04 2B 16 7E F9 09
IL_030: 00 04 FE 06 67 14 00 06 73 8D 05 00 0A 25 80 FB
IL_040: 09 00 04 14 18 73 8E 05 00 0A 02 FE 06 1C 06 00
IL_050: 06 73 8D 05 00 0A 14 17 28 CA 00 00 2B 2A
```

其中 `IL_03D` 的 `brtrue.s +0xFB` 会跳到方法体之外（方法体只有 0x5E 字节），
即上游放置了越界分支——这就是该入口被"锁死"的方式之一。

---

## 5. 生成的自动补丁版

```text
路径    E:\pxl-g\Plain Craft Launcher 2.autopatched.exe
大小    5,981,184 字节 (0x5B4400)
SHA256  3BFFCB201575822F9082F0AFC6361A909BDFCAA222A52178307FB0AA43747978
```

### 5.1 与手工补丁版的比对

2026-10-20 记录的手工补丁版：

```text
文件    E:\pxl-g\Plain Craft Launcher 2.patched.exe   （当前目录中已不存在）
大小    5,981,184 字节 (0x5B4400)
SHA256  3BFFCB201575822F9082F0AFC6361A909BDFCAA222A52178307FB0AA43747978
```

**结论：自动生成版与手工补丁版逐字节一致（SHA256 完全相同）。**

### 5.2 Section 头变化

| Section | VA | VirtualSize | RawPtr | RawSize | Characteristics |
| --- | --- | --- | --- | --- | --- |
| `.text` | `0x2000` | `0x581BD0` | `0x200` | `0x581C00` | `0x60000020`（未变） |
| `.rsrc` | `0x584000` | `0x31FB4` | `0x581E00` | `0x32000` | `0x40000040`（未变） |
| `.reloc` | `0x5B6000` | `0xC` → **`0x40C`** | `0x5B3E00` | `0x200` → **`0x600`** | `0x42000040` → **`0x60000020`** |

文件末尾随之从 `0x5B4000` 扩展到 `0x5B4400`（`0x400` 字节）。
`SizeOfImage` 保持 `0x5B8000`——新的虚拟末尾 `0x5B63E4` 仍在其范围内，
因此不需要修改。

### 5.3 `MethodDef` RVA 更新

```text
文件偏移  0x000AFD58
原值      0x00012110
新值      0x005B600C
```

新方法体落在 `.reloc` 内的相对偏移 `0xC`，即文件偏移 `0x005B3E0C`。

---

## 6. IL / 异常表验证

### 6.1 `LoaderInit`（file off `0x0002C0B4`，fat header 12 字节）

```text
codesize = 51 (0x33)
maxstack = 9
IL:
  02 28 12 05 00 06
  02 02 6F 07 06 00 06
  02 6F 05 06 00 06
  02 6F 51 05 00 06
  14 7E 0F 04 00 04
  02 FE 06 1C 06 00 06
  73 8D 05 00 0A
  14 17 28 CA 00 00 2B
  2A
```

### 6.2 `ModpackInstall`（新方法体 file off `0x005B3E0C`）

```text
codesize = 896 (0x380)
maxstack = 5
localSig = 0x11000068
```

分发代码入口：

```text
IL[0x2DA..0x2DE]: 11 04 45 0A 00
                  ldloc.s 4 ; switch (10) ; <40 字节跳转表>
```

外层 `finally` 块与返回点：

```text
IL[0x374..0x37F]: 07 2C 06 07 6F 6A 03 00 0A DC 06 2A
                  ldloc.1
                  brfalse.s +6
                  ldloc.1
                  callvirt 0x0A00036A
                  stloc.0
                  endfinally
                  ldloc.0
                  ret
```

限制桩仍保留在 `IL_02DA`（`ldstr / newobj / throw`），
由 `catch System.Exception` 子句覆盖，与手工补丁版行为一致。

### 6.3 异常表（fat format，紧随 IL，4 字节对齐）

```text
kind = 0x41 (fat), dataSize = 0x4C

clause flags=0x2  try=(323,307)  handler=(630,12)   cls=0x00000000   finally
clause flags=0x0  try=(109,535)  handler=(644,86)   cls=0x01000033   catch System.Exception
clause flags=0x2  try=(39,845)   handler=(884,10)   cls=0x00000000   finally
```

- 外层 `finally` 的 handler 偏移 = `884` = **`0x374`**；
- 外层 `finally` 的 try 区间 = `[39, 39+845) = [0x27, 0x374)`，正好覆盖整个 switch 分发区；
- `catch` 子句的 handler 区间 = `[644, 730) = [0x284, 0x2DA)`，正好是限制桩之前的区段。

---

## 7. JIT 验证

使用 `ildump\jit.exe` 对输出文件中的两个方法强制编译：

```text
JIT OK 0x06000513 PCL.PageDownloadInstall::LoaderInit
JIT OK 0x060001F0 PCL.ModModpack::ModpackInstall
```

说明：`jit.exe` 需要 `Newtonsoft.Json 13.0.0.0`；测试时在临时 `ildump` 目录中放置了
net45 版本的 `Newtonsoft.Json.dll`。该 DLL 只是 JIT 测试依赖，**不属于补丁内容**。

---

## 8. 幂等与安全失败测试

### 8.1 幂等：把已补丁文件再次输入

```text
> pclautopatch.exe "E:\pxl-g\Plain Craft Launcher 2.autopatched.exe" --verify
State: LoaderInit=already patched, ModpackInstall=already patched
Verify-only: no output written.
退出码 0
```

不传 `--verify` 时会原样复制到输出路径，不做二次修改。

### 8.2 模式不符：破坏 `ControlInit` 的调用 opcode

把原文件 `LoaderInit` 的 `ControlInit` 调用 opcode（文件偏移 `0x2C0C1`）由 `0x28` 改为 `0x29`：

```text
ERROR: LoaderInit: ControlInit pattern mismatch
退出码 1
输出文件：未创建
```

### 8.3 输入路径 == 输出路径

```text
ERROR: output path must differ from input path; the input is never modified
退出码 1
原版文件哈希保持不变。
```

### 8.4 等价路径写法（2026-10-21 新增）

早期实现用纯字符串比较判断路径是否相同，下列等价写法可以绕过检查。
现已改为路径规范化比较，以下三种写法**均被拦截**（退出码 1，原文件哈希不变）：

| 输入 | 输出 | 结果 |
| --- | --- | --- |
| `E:\pxl-g\Plain Craft Launcher 2.exe` | `E:/pxl-g/Plain Craft Launcher 2.exe` | `ERROR: output path must differ from input path` |
| `Plain Craft Launcher 2.exe`（相对） | `E:\pxl-g\Plain Craft Launcher 2.exe` | 同上 |
| `E:\pxl-g\Plain Craft Launcher 2.exe` | `E:\pxl-g\.\Plain Craft Launcher 2.exe` | 同上 |

---

## 9. 可重复性验证（2026-10-21）

从源码重新构建（零警告），对原版文件重新执行补丁：

```text
构建      g++ 16.2.0 -std=c++17 -O2 -Wall -Wextra -static   → 成功，0 警告
输出大小  5,981,184 字节 (0x5B4400)
输出 SHA256 3BFFCB201575822F9082F0AFC6361A909BDFCAA222A52178307FB0AA43747978
```

与 2026-10-20 记录的自动补丁版、以及手工补丁版三者**完全一致**，
说明结果可稳定复现，与构建环境无关。

---

## 10. 保留情况

```text
E:\pxl-g\Plain Craft Launcher 2.exe            未修改，哈希仍为 6B6E...
E:\pxl-g\Plain Craft Launcher 2.autopatched.exe 自动生成版，哈希 3BFF...
E:\pxl-g\pclautopatch.exe                       构建产物（不纳入版本控制）
E:\pxl-g\pclautopatch.cpp                       工具源码
E:\pxl-g\build.bat                              构建脚本
E:\pxl-g\README.md / VERIFY.md                  文档
```

---

## 11. 结论

1. 工具能够稳定、可重复地把 PCL 2.99.0.0 的两个被锁死的入口恢复为可用状态；
2. 输出与人工手工补丁的结果**逐字节一致**，且已通过 CLR JIT 编译验证；
3. 在任何检测失败、模式不符、路径冲突的情况下，工具都**先报错退出、不留半成品**；
4. 输入文件在整个流程中始终保持原样（哈希不变）。

> 本工具绕过上游"为遵守相关法律法规"的限制，仅供本地研究；
> **不要分发修改后的二进制**。
