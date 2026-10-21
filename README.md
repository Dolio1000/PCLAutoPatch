# PCLAutoPatch

> 自动定位并修复 PCL 2.99.0.0（Plain Craft Launcher 2）中被上游故意破坏的两个下载 / 整合包入口，
> 输出一个独立的补丁副本，**绝不修改输入文件**。

**工具本体**：`pclautopatch.cpp`（单文件 C++17，无第三方依赖，只依赖标准库与 Win32 文件系统 API）

---

## ⚠️ 声明与使用范围

- 本工具用于**本地研究**，分析 .NET 程序集的 PE / CLR 元数据与 IL 结构。
- 本工具绕过上游"为遵守相关法律法规"而设置的访问限制，这可能与上游的许可条款相冲突。
- **不要分发修改后的二进制文件。** 原版 PCL 请从官方渠道获取。
- 仅支持面向 .NET Framework 的 PCL 2.99.0.0；方法名、字段名、IL 模式或方法体大小一旦变化，
  工具会**报错退出**，绝不猜测、也绝不写出半成品文件。

---

## 目录

| 章节 | 内容 |
| --- | --- |
| [1. 功能概述](#1-功能概述) | 工具解决什么问题 |
| [2. 项目结构](#2-项目结构) | 仓库里有哪些文件 |
| [3. 构建](#3-构建) | 编译方法与工具链要求 |
| [4. 使用](#4-使用) | 命令行参数与示例 |
| [5. 工作原理](#5-工作原理) | 元数据解析、IL 重建、方法体重定位 |
| [6. PCL 2.99.0.0 目标数据](#6-pcl-29900-目标数据) | 定位到的 token / RVA / 偏移 |
| [7. 安全保证](#7-安全保证) | 工具承诺的不变量 |
| [8. 限制与已知问题](#8-限制与已知问题) | 边界条件与代码审查结论 |
| [9. 验证结果摘要](#9-验证结果摘要) | 与手工补丁版的比对结论 |
| [10. 仓库约定](#10-仓库约定) | Git 与文件收录规则 |

---

## 1. 功能概述

PCL 2.99.0.0 在上游发布时，对两处关键入口做了处理，使得这两条路径**永远走不通**：

| # | 目标 | 类型 / 签名 | 问题 |
| --- | --- | --- | --- |
| 1 | `LoaderInit` | `PCL.PageDownloadInstall.LoaderInit()` | 方法体被塞入指向越界分支的垃圾 IL，JIT 必然失败 |
| 2 | `ModpackInstall` | `PCL.ModModpack.ModpackInstall(String, String, String)` | 方法体尾部的 `ldstr / newobj / throw` 限制桩，在真正分发到各安装器之前直接抛出异常 |

`PCLAutoPatch` 解析程序集的元数据，按**类型名、方法名、字段名**（而不是硬编码文件偏移）定位这两个方法，
然后：

1. 重建 `LoaderInit` 的 51 字节合法 IL，原地写回并更新 `code size`；
2. 重建 `ModpackInstall` 的 `switch` 分发逻辑（生成 0x380 字节 IL），
   修正异常表（exception table），并把新方法体搬到最后一个 PE section（PCL 2.99 的 `.reloc`），
   同步更新 `MethodDef` 的 RVA、section header 与 `SizeOfImage`；
3. **在落盘之前重新解析一遍输出字节**，逐项校验方法体、`MethodDef` RVA 与 `finally` 偏移；
   任何一项不通过就不会产生输出文件。

工具只读取输入文件，默认输出 `<输入文件名>.autopatched.exe`。

---

## 2. 项目结构

```text
pxl-g/
├── README.md                          # 本文档
├── VERIFY.md                          # 完整验证记录
├── .gitignore                         # 排除二进制产物
├── build.bat                          # 一键构建脚本
├── pclautopatch.cpp                   # 工具源码（唯一源文件）
├── pclautopatch.exe                   # 构建产物            [不纳入版本控制]
├── Plain Craft Launcher 2.exe         # 原版 PCL            [不纳入版本控制]
└── Plain Craft Launcher 2.autopatched.exe  # 自动补丁版   [不纳入版本控制]
```

> 三个 `.exe` 均属于二进制产物或第三方程序，**不提交到 Git**（见 [§10](#10-仓库约定)）。

---

## 3. 构建

### 3.1 一键构建

```bat
build.bat
```

脚本优先使用 MSYS2 UCRT64 工具链（`C:\msys64\ucrt64\bin\g++.exe`），
找不到时回退到 `PATH` 上的 `g++`。

### 3.2 手工构建

```bat
C:\msys64\ucrt64\bin\g++.exe -std=c++17 -O2 -Wall -Wextra -static ^
    -o pclautopatch.exe pclautopatch.cpp
```

### 3.3 工具链要求

| 项目 | 要求 |
| --- | --- |
| 编译器 | 支持 C++17 的 GCC（需支持 `<filesystem>`）或 MSVC |
| 已验证版本 | MSYS2 UCRT64 **g++ 16.2.0**（2026-10-20 / 2026-10-21 实测） |
| 编译选项 | `-std=c++17 -O2 -Wall -Wextra -static` |
| 警告 | 上述选项下**零警告**（`-Wall -Wextra`） |
| 依赖 | 仅标准库；无第三方库 |
`-static` 会生成约 3.2 MB 的独立可执行文件，不依赖运行时的 `libstdc++` / `libgcc` DLL。

---

## 4. 使用

### 4.1 命令行

```text
pclautopatch.exe <input.exe> [output.exe] [--verify] [--force] [--verbose]
```

| 参数 | 说明 |
| --- | --- |
| `<input.exe>` | 输入的 PCL 可执行文件（必填，只读） |
| `[output.exe]` | 输出路径；缺省为输入文件同目录下的 `<文件名>.autopatched.exe` |
| `--verify` | 只解析并报告检测结果，**不写任何输出文件** |
| `--force` | 允许覆盖已存在的输出文件 |
| `--verbose` | 打印补丁细节（IL 字节、新 RVA、section 变化等） |
| `--help` / `-h` | 显示帮助 |

退出码：`0` 成功；`1` 出错（已打印 `ERROR: ...`）；`2` 未提供输入文件。

### 4.2 示例

```bat
:: 只做检测，不写文件
pclautopatch.exe "E:\pxl-g\Plain Craft Launcher 2.exe" --verify

:: 使用默认输出名
pclautopatch.exe "E:\pxl-g\Plain Craft Launcher 2.exe"

:: 指定输出路径
pclautopatch.exe "E:\pxl-g\Plain Craft Launcher 2.exe" "E:\pxl-g\out.exe"

:: 覆盖已有输出，并打印细节
pclautopatch.exe "E:\pxl-g\Plain Craft Launcher 2.exe" "E:\pxl-g\out.exe" --force --verbose
```

### 4.3 典型输出

```text
Input: E:\pxl-g\Plain Craft Launcher 2.exe (5980160 bytes)
PE: sections=3 sectionAlign=0x2000 fileAlign=0x200 imageSize=0x5B8000
Metadata: typeDef=665 methodDef=6339 field=3603
Types:
  PageDownloadInstall token=0x02000059
  ModModpack          token=0x02000038
  ModDownload         token=0x0200007E
Methods:
  LoaderInit    token=0x06000513 rva=0x0002DEB4 code=0x5E
  ModpackInstall token=0x060001F0 rva=0x00012110 code=0x2EF
Field:
  DlClientListLoader token=0x0400040F type=PCL.ModDownload
Sections:
  .text VA=0x2000 VS=0x581BD0 RawPtr=0x200 RawSize=0x581C00 Char=0x60000020
  .rsrc VA=0x584000 VS=0x31FB4 RawPtr=0x581E00 RawSize=0x32000 Char=0x40000040
  .reloc VA=0x5B6000 VS=0xC RawPtr=0x5B3E00 RawSize=0x200 Char=0x42000040
State: LoaderInit=original, ModpackInstall=original
  LoaderInit tokens:
    ControlInit       0x06000512
    ...
  ModpackInstall patch: code=0x380 body=984 newRVA=0x005B600C fileOff=0x5B3E0C
OK: wrote E:\pxl-g\Plain Craft Launcher 2.autopatched.exe (5981184 bytes)
```

---

## 5. 工作原理

### 5.1 PE / CLR 元数据解析

工具自带一个精简的 PE + CLI metadata 解析器，不依赖任何逆向框架：

1. 读取 `e_lfanew` → PE 头 → Optional Header（`0x10B` PE32 / `0x20B` PE32+）→ Section Table；
2. 通过第 15 号数据目录定位 CLI Header（`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`），
   再定位 Metadata 根（`BSJB`）；
3. 遍历 Metadata Stream（`#~` / `#-`、`#Strings`、`#Blob`、`#US`），
   依据 `HeapSizes` 与 `Valid` 位图计算每张表的行数、索引宽度与起始偏移；
4. 解析 `TypeDef`(0x02)、`Field`(0x04)、`MethodDef`(0x06) 三张表，
   并按 `FieldList` / `MethodList` 的区间把字段、方法归属到各自的类型。

索引宽度（2 字节 / 4 字节）与 coded index 的 tag 位宽都按 ECMA-335 规则动态计算，
因此工具不依赖某个特定版本的布局。

### 5.2 `LoaderInit` 补丁

1. 校验原始方法体恰好是 0x5E 字节，并逐段比对 IL 模式：
   `ControlInit` 调用、三个 getter 的 `callvirt`、占位字符串 `ldstr`、
   `ldftn` lambda、`Action` 构造器、结尾 `ret`；
2. 从**原方法体的 IL 字节里**提取所需 token（`ControlInit`、`get_LoadMinecraft`、
   `get_PanLoad`、`get_PanAllBack`、`_Lambda$__R3-4`、`Action::.ctor`、`PageLoaderInit`），
   按字段名解析 `PCL.ModDownload.DlClientListLoader` 的字段 token；
3. 重建 51 字节 IL，原地写回并更新 fat header 的 code size（0x5E → 0x33）：

   ```text
   02 28 12 05 00 06      ldarg.0; call ControlInit
   02 02 6F 07 06 00 06   ldarg.0; ldarg.0; callvirt get_LoadMinecraft
   02 6F 05 06 00 06      ldarg.0; callvirt get_PanLoad
   02 6F 51 05 00 06      ldarg.0; callvirt get_PanAllBack
   14 7E 0F 04 00 04      ldnull; ldsfld DlClientListLoader
   02 FE 06 1C 06 00 06   ldarg.0; ldftn _Lambda$__R3-4
   73 8D 05 00 0A         newobj Action::.ctor
   14 17 28 CA 00 00 2B   ldnull; ldc.i4.1; call PageLoaderInit
   2A                     ret
   ```

### 5.3 `ModpackInstall` 补丁

1. 在 `PCL.ModModpack` 中按方法名选择**三参数**版本
   （另有 0 参数提示桩，用方法体大小 0x2EF / 0x380 区分）；
2. 校验 `IL_02DA` 的 `ldstr / newobj / throw` 限制桩，以及 `IL_02E5` 的 `finally` 块；
3. 按名称解析 7 个安装器方法：
   `InstallPackCurseForge`、`InstallPackHMCL`、`InstallPackMMC`、`InstallPackMCBBS`、
   `InstallPackModrinth`、`InstallPackLauncherPack`、`InstallPackCompress`；
4. 重建 `switch` 分发，跳转表按如下映射：

   | 源类型值 | 目标安装器 |
   | --- | --- |
   | 0 | `InstallPackCurseForge` |
   | 1 | `InstallPackHMCL` |
   | 2 | `InstallPackMMC` |
   | 3 | `InstallPackMCBBS` |
   | 4 | `InstallPackModrinth` |
   | 5 – 8 | `InstallPackCompress`（默认分支） |
   | 9 | `InstallPackLauncherPack` |

   每个分支调用安装器后 `stloc.0` 保存结果，再 `leave` 到统一的返回点；
5. 生成 0x380 字节 IL（0x2DA 原始前缀 + 0x9A 分发代码 + 10 字节 finally 块 + `ldloc.0; ret`）；
6. 复制并修正异常表：把外层 `finally` 的 try 长度延伸到新的 finally 起点，
   并把 handler 偏移 / 长度改到新位置；
7. 补丁后的限制桩仍保留在 `IL_02DA`，由 `catch System.Exception` 子句覆盖，
   行为与手工补丁版一致。

### 5.4 方法体重定位

新方法体（984 字节）比原位置空间大，需要搬迁：

1. 选择**raw data 偏移最大**的 section 作为载体（PCL 2.99 是 `.reloc`）；
2. 要求该 section 的 raw data 正好延伸到文件末尾
   （`rawPtr + rawSize == fileSize`），否则拒绝扩展（防止踩到 overlay 或异常布局）；
3. 在 section 末尾追加方法体，同步更新 section header 的
   `VirtualSize` / `SizeOfRawData` / `Characteristics`（`.reloc` 由 `0x42000040` 改为 `0x60000020`，
   使新方法体可执行）；
4. 更新 `MethodDef` 表中该方法的 `RVA`；
5. 必要时更新 Optional Header 的 `SizeOfImage`（本例中无需改动，
   因为新的虚拟末尾仍在原 `SizeOfImage` 之内）。

### 5.5 落盘前复验

输出字节在写文件之前会被**重新解析一遍**，并逐项核对：

- `LoaderInit` 的方法体字节与刚生成的补丁逐字节一致；
- `ModpackInstall` 的 code size、switch 模式、`MethodDef` RVA；
- 异常表中 `try offset == 39` 的那条 `finally` 子句，其 handler 偏移等于新的 finally 起点。

任何一项不符都会 `ERROR` 退出，**不会留下半成品文件**。

---

## 6. PCL 2.99.0.0 目标数据

以下为工具在 2.99.0.0 上实测定位到的数据（由名称解析得到，不是硬编码）：

### 6.1 类型与字段

| 项 | token | 说明 |
| --- | --- | --- |
| `PCL.PageDownloadInstall` | `0x02000059` | 目标类型 |
| `PCL.ModModpack` | `0x02000038` | 目标类型 |
| `PCL.ModDownload` | `0x0200007E` | 目标类型 |
| `PCL.ModDownload.DlClientListLoader` | `0x0400040F` | 目标字段 |

### 6.2 方法

| 方法 | token | 原始 RVA | 原始 file off | 原始 code size | 补丁后 |
| --- | --- | --- | --- | --- | --- |
| `LoaderInit` | `0x06000513` | `0x0002DEB4` | `0x0002C0B4` | `0x5E` | code size `0x33`（原地） |
| `ModpackInstall(String,String,String)` | `0x060001F0` | `0x00012110` | `0x00010310` | `0x2EF` | code size `0x380`，新 RVA `0x005B600C`，新 file off `0x005B3E0C` |

### 6.3 `LoaderInit` 中提取 / 重建用到的 token

| 名称 | token |
| --- | --- |
| `ControlInit` | `0x06000512` |
| `get_LoadMinecraft` | `0x06000607` |
| `get_PanLoad` | `0x06000605` |
| `get_PanAllBack` | `0x06000551` |
| `_Lambda$__R3-4` | `0x0600061C` |
| `Action::.ctor` | `0x0A00058D` |
| `PageLoaderInit` | `0x2B0000CA` |

### 6.4 安装器方法 token

| 方法 | token |
| --- | --- |
| `InstallPackCurseForge` | `0x060001F4` |
| `InstallPackModrinth` | `0x060001F5` |
| `InstallPackHMCL` | `0x060001F6` |
| `InstallPackMMC` | `0x060001F7` |
| `InstallPackMCBBS` | `0x060001F8` |
| `InstallPackLauncherPack` | `0x060001F9` |
| `InstallPackCompress` | `0x060001FA` |

### 6.5 PE 布局

| Section | VA | VirtualSize | RawPtr | RawSize | Characteristics |
| --- | --- | --- | --- | --- | --- |
| `.text`（原版） | `0x2000` | `0x581BD0` | `0x200` | `0x581C00` | `0x60000020` |
| `.rsrc`（原版） | `0x584000` | `0x31FB4` | `0x581E00` | `0x32000` | `0x40000040` |
| `.reloc`（原版） | `0x5B6000` | `0xC` | `0x5B3E00` | `0x200` | `0x42000040` |
| `.reloc`（补丁后） | `0x5B6000` | `0x40C` | `0x5B3E00` | `0x600` | `0x60000020` |

`SectionAlignment = 0x2000`，`FileAlignment = 0x200`，`SizeOfImage = 0x5B8000`（前后一致）。

---

## 7. 安全保证

工具对使用者承诺以下不变量：

| 保证 | 实现方式 |
| --- | --- |
| **绝不修改输入文件** | 输入先完整读入内存，所有修改都在副本上进行；输出路径与输入路径经**规范化后**比对，相同则拒绝执行 |
| **不产生半成品** | 写盘前对输出字节重新解析并逐项校验，任何一步失败即报错退出 |
| **不猜测、不硬编码** | 全部按类型名 / 方法名 / 字段名解析；IL 模式或方法体大小不匹配时直接报错 |
| **默认不覆盖** | 输出文件已存在时拒绝执行，除非显式 `--force` |
| **幂等** | 对已补丁的文件再次运行，会识别为 `already patched` 并原样复制，不会二次修改 |

> 早期版本用纯字符串比较判断"输入路径 == 输出路径"，`E:\dir\x.exe` 与 `E:/dir/x.exe`
> 这类等价写法可以绕过该检查，从而把输出写回输入文件。
> 现已改为使用 `<filesystem>` 做路径规范化后比较，参见 [§8](#8-限制与已知问题)。

---

## 8. 限制与已知问题

### 8.1 功能限制

- 仅面向 **.NET Framework** 的 PCL **2.99.0.0**；
- 假定 `LoaderInit` 与 `ModpackInstall(String,String,String)` 的源码结构不变。
  若方法名、字段名、7 个 `InstallPack*` 名称、IL 模式或方法体大小发生变化，工具报错退出；
- 要求最后一个 PE section 的 raw data 正好延伸到文件末尾（PCL 2.99 的 `.reloc` 满足）。
  存在 overlay 或异常 section 布局时，工具拒绝扩展；
- 载体 section 的 `Characteristics` 被**硬编码**为 `0x60000020`。
  这对 PCL 2.99 的 `.reloc` 是正确的（方法体必须可执行），
  但换到其他 section 布局时不会被自动适配。

### 8.2 代码审查结论（2026-10-21）

对 `pclautopatch.cpp` 做了一轮完整复查，结论如下：

**已修复**

| # | 问题 | 影响 | 处理 |
| --- | --- | --- | --- |
| 1 | 输出路径与输入路径的比较是纯字符串比较 | `E:\dir\x.exe` 与 `E:/dir/x.exe`、`x.exe` 与 `.\x.exe` 等价写法可绕过检查，导致**输出覆盖输入**，破坏"输入永不被修改"的承诺 | 改为 `std::filesystem::weakly_canonical()` 规范化后比较（`canonicalPath()`），三种绕过写法均已复测拦截 |
| 2 | "已补丁"分支里有一处重复且不可达的死代码 | 无功能影响 | 删除 |
| 3 | `--verbose` 只打印一句无信息量的提示 | 可用性 | 改为打印 IL 字节、code size 变化、新 RVA、section 变化等实际补丁细节 |
| 4 | `build.bat` 在找不到编译器时只会抛出 cmd 的原始报错 | 可用性 | 补充明确的错误提示 |

**已知但有意保留**

| # | 问题 | 说明 |
| --- | --- | --- |
| 5 | `PEImage::rowSize()` 对表号 ≥ 0x07（`ModuleRef` / `Param` / `InterfaceImpl` …）返回 0 | 计算表起始偏移时，这些表之后的偏移会失真。当前只使用 `0x00` / `0x02` / `0x04` / `0x06` 四张表，且它们都排在 `0x07` 之前，因此不受影响。若日后要解析更多表，必须先补齐 `rowSize()` |
| 6 | `isLoaderPatched()` / `isModpackPatched()` 只比对 4–5 个字节的特征 | 是"已补丁"判定用的启发式指纹，理论上存在误判的可能。对本工具处理的确定二进制而言误判概率可忽略；误判方向是"跳过补丁"，不会破坏文件 |
| 7 | `std::ifstream(outPath).good()` 被当作"文件是否存在"的判据 | 若输出路径是一个目录或权限不足，`good()` 为假，工具继续往下走并在写入时报 `cannot open output`。属报错时机偏晚，不影响正确性 |
| 8 | 异常表搜索依赖魔数 `try offset == 39` | 该魔数来自 PCL 2.99 的实际布局；工具已用 `IL_02E5` 的模式校验把两者绑定在一起，布局变化时会先在模式校验阶段失败 |

**未发现问题的部分**

- 所有读写均有边界检查（`rd16` / `rd32` / `rd64` / `wr32` / `readCString`）；
- PE / CLR 头部偏移计算逐项核对过 ECMA-335；
- IL 重建的分支偏移、跳转表基址、`leave` 目标经手工反汇编复核无误；
- 异常表 4 字节对齐基于方法体起点（fat header 为 12 字节，本身是 4 的倍数），语义正确；
- `-Wall -Wextra` 下零警告。

---

## 9. 验证结果摘要

完整记录见 [VERIFY.md](VERIFY.md)。核心结论：

```text
原版       5,980,160 (0x5B4000)  SHA256 6B6E1260CB5A1D6A303855F1C60CAB3D0BC1AEBBA7E40A964180188B271E7386
自动补丁版 5,981,184 (0x5B4400)  SHA256 3BFFCB201575822F9082F0AFC6361A909BDFCAA222A52178307FB0AA43747978
```

- 自动生成版与**手工补丁版逐字节一致**（SHA256 完全相同）；
- `LoaderInit` code size = 0x33、`ModpackInstall` code size = 0x380；
- `ModpackInstall` 异常表 3 个子句，外层 `finally` handler 偏移 `0x374`；
- 两个方法均已通过 `jit.exe` 强制编译验证（JIT OK）；
- 幂等性、安全失败路径（模式不符、输入输出同路径）均已复测通过。

---

## 10. 仓库约定

- **不提交任何二进制**：三个 `.exe`（构建产物 `pclautopatch.exe`、
  原版 `Plain Craft Launcher 2.exe`、自动补丁版 `Plain Craft Launcher 2.autopatched.exe`）
  通过 `.gitignore` 排除。仓库只保留源码、构建脚本与文档；
- 文档统一使用 Markdown（`README.md` / `VERIFY.md`），不使用纯文本；
- `build.bat` 与源码保持同步，修改源码后请重新构建并复跑验证流程；
- 修改 `pclautopatch.cpp` 后，请至少执行一次
  `pclautopatch.exe "Plain Craft Launcher 2.exe" --verify`，
  并确认输出 SHA256 仍为 `3BFFCB20...4379478`（若改动不影响补丁结果）。
