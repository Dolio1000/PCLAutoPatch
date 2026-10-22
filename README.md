# PCLAutoPatch

> 一个**可复刻的逆向工程记录**，以及由它直接生成的工具：在没有符号、没有源码、不能调试的前提下，
> 定位 PCL 2.99.0.0 里被上游锁死的三个下载 / 整合包入口，重建它们的 IL，安全地搬进 PE 文件，并自证输出可用。
>
> 重点不是"工具做了什么"，而是**"为什么这样做、凭什么这样做、换一版怎么再做一遍"**。

**工具本体**：`pclautopatch.cpp`（单文件 C++17，仅依赖标准库）

---

## ⚠️ 声明与使用范围

- 用于**本地研究**：分析 .NET 程序集的 PE / CLR 元数据与 IL 结构。
- 绕过上游"为遵守相关法律法规"设置的访问限制，可能与上游许可条款冲突。
- **不要分发修改后的二进制文件。** 原版 PCL 请从官方渠道获取。
- 工具**只读**输入文件；任何一步校验失败都会在写盘前中止，不产生半成品。

---

## 快速开始

### 构建

```bat
build.bat
```

或手工：

```bat
C:\msys64\ucrt64\bin\g++.exe -std=c++17 -O2 -Wall -Wextra -static ^
    -o pclautopatch.exe pclautopatch.cpp
```

已验证 MSYS2 UCRT64 g++ 16.2.0，`-Wall -Wextra` 下零警告。

### 运行

```bat
pclautopatch.exe "Plain Craft Launcher 2.exe"
:: -> Plain Craft Launcher 2.autopatched.exe
```

### 参数

| 参数 | 说明 |
| --- | --- |
| 第 2 个位置参数 | 输出路径（默认 `<输入名>.autopatched.exe`） |
| `--probe` | 完整分析并打印全部推导结果，**不写文件**（适配新版本时先用它） |
| `--verify` | 只检查是否已打补丁，不写文件 |
| `--force` | 允许覆盖已存在的输出 |
| `--verbose` | 打印新 RVA、文件偏移等细节 |

### 典型输出

```text
State: LoaderInit=original, ModpackInstall=original, Save_Click=original
ModpackInstall patch: stub=IL_0x2DA finally=IL_0x374+0xA formatLocal=4 formats=10 code=0x380
Save_Click patch: modpack resource type = 2 (from the save worker's switch table; ...)
OK: wrote Plain Craft Launcher 2.autopatched.exe (5981696 bytes)
```

---

## 目录

| 章节 | 内容 |
| --- | --- |
| [1. 问题](#1-问题上游到底做了什么) | 上游锁死了什么 |
| [2. 不变量](#2-不变量工具必须始终成立的事) | 工具必须始终成立的事 |
| [3. 定位方法论](#3-定位方法论没有符号时怎么找到代码) | 名称 → token → 方法头 → IL |
| [4. 三个补丁的推导](#4-三个补丁的推导观察--假设--验证--重建) | 观察 → 假设 → 验证 → 重建 |
| [5. 重建 IL](#5-重建-il) | 合成、搬迁、异常表、castclass |
| [6. 验证方法论](#6-验证方法论凭什么说输出是对的) | 抽象解释、重解析、负向测试 |
| [7. 版本适配](#7-版本适配pcl-更新后怎么办) | 新版本来了怎么继续 |
| [8. 从零复刻](#8-从零复刻步骤清单) | 按文档重写一遍的步骤 |
| [9. 目标数据](#9-目标数据pcl-29900-实测) | 实测 token / 偏移 |
| [10. 限制](#10-限制与已知问题) | 边界条件 |

---

## 1. 问题：上游到底做了什么

三条与"下载 / 安装"相关的路径被堵死，且堵法各不相同——这决定了补丁手法必须各不相同。

| # | 入口 | 签名 | 上游做了什么 |
| --- | --- | --- | --- |
| 1 | `PCL.PageDownloadInstall.LoaderInit` | `()` | 方法体尾部被塞进指向越界目标的分支，JIT 必然失败 → 下载页加载不出来 |
| 2 | `PCL.ModModpack.ModpackInstall` | `(String, String, String)` | 尾部是 `ldstr <限制文案> / newobj / throw`，在分发到真正的安装器前抛异常 |
| 3 | `PCL.PageDownloadResourceDetail.Save_Click` | `(Object, RoutedEventArgs)` | 整合包版本条目的点击被接到"另存为"；真正的 `Install_Click` 仍在程序集里，但**没有任何 `ldftn` 引用它** → 死代码 |

三条都不是"一个 if"：第 1 条是垃圾 IL，必须整段重写；第 2 条只要替换尾部，但替换后变大，必须搬迁；
第 3 条目标方法还完整，只需在入口处加分流。所以是三种手术，不是一种通用改法。

---

## 2. 不变量：工具必须始终成立的事

1. **输入只读**；输出路径与输入等价（大小写、`./`、相对路径）时直接拒绝。
2. **不留半成品**：分析、生成、校验全在内存里，只有最后一步 `writeFile`；任何 `fail()` 都在写盘之前。
3. **不猜**：token / 偏移 / 数值只能来自元数据名称、签名 blob、`#US` 字面量、指令形状或枚举常量。
4. **幂等**：用语义判据判断"是否已打过补丁"（§6.4）。
5. **自证**：重建的方法体在写盘前必须通过内置 IL 校验器（§6.1）。

---

## 3. 定位方法论：没有符号时怎么找到代码

### 3.1 链路

```
已知字符串（类型名 / 方法名 / 字面量）
   ↓ #Strings 堆
TypeDef / MethodDef / Field 行
   ↓ RVA
方法头（tiny / fat）
   ↓ codeSize
IL 字节 ──→ 反汇编 ──→ 指令形状匹配 ──→ token / 偏移 / 局部变量
```

只走这一条路，**从不使用上一次逆向记下来的文件偏移**。

### 3.2 为什么放弃偏移

同一个 VB 源码，换编译器版本或改一行无关代码，就可能出现：方法体长度变化（`.text` 整体位移）、
局部变量编号变化（`ldloc.s 4` → `ldloc.s 5`）、常量折叠变化（`ldc.i4.1` → `ldc.i4 1`，2→5 字节）、
`br.s` 因距离超 127 升级为 `br`（2→5 字节）。任何一条都会让"按偏移改字节"失效。

### 3.3 五类锚点

| 锚点 | 用途 | 例子 |
| --- | --- | --- |
| 元数据名称 | 找类型 / 方法 / 字段 | `PCL.ModModpack.ModpackInstall` |
| `#US` 字面量 | 找字符串、给 `ldstr` 取 token | `"Parent"` / `"Tag"` / `"整合包"` |
| 指令序列 | 找结构性代码块 | `ldstr/newobj/throw`；`ldloc/brfalse/ldloc/call/endfinally` |
| 数据流 | 找"哪个局部变量是枚举值" | 把常量存进同一局部变量的一组 `stloc` |
| 元数据表 | 枚举字面量、调用签名 | `Constant` 表、`MethodDef.Signature` |

### 3.4 必须先写 IL 解码器

按形状匹配就必须知道每条指令多长。规则：单字节 opcode + 0/1/2/4/8 字节操作数；`0xFE` 前缀双字节；
`switch` 特例（4 字节 case 数 + 4×N 表）；`ldc.i8`/`ldc.r8` 8 字节。
解码失败（截断、非法 switch）一律报错——**宁可停下，也不在错误边界上匹配**。

---

## 4. 三个补丁的推导（观察 → 假设 → 验证 → 重建）

### 4.1 `LoaderInit`：把垃圾 IL 换成合法 IL

**观察**（94 字节）：前半段是 `ControlInit` + 三个 getter（正常）；后半段被换成
"`ldstr "关闭下载"` → 构造对话框 → `PageLoaderInit`"。

**重建**（51 字节 → **原地重写**）：

```
ldarg.0 / call ControlInit
ldarg.0 / ldarg.0 / callvirt get_LoadMinecraft
ldarg.0 / callvirt get_PanLoad
ldarg.0 / callvirt get_PanAllBack
ldnull / stsfld DlClientListLoader        ← 复位下载列表加载器
ldarg.0 / ldftn <lambda> / newobj Action
ldnull / <原样的优先级常量> / call PageLoaderInit
ret
```

不猜的设计：`ControlInit` 与三个 getter 按**名称**解析并与体里的 token 交叉校验；lambda 取
**体里唯一的 `ldftn`**（名字是编译器生成的，不可依赖）；`Action::.ctor` / `PageLoaderInit` 取
**尾部那条 `newobj` / `call`**；优先级常量**原样复制那一条指令的字节**；新体不得超原体长度。

### 4.2 `ModpackInstall`：把 `throw` 换成 `switch`

**观察**（751 字节）：前半段是完整的"识别格式 → 解压 → 复制"，末尾是

```
ldloc.s 9 / newobj <Exception> / throw          ← 构造限制消息
ldstr "<限制文案>" / newobj <Exception> / throw  ← 所有成功分支最终流到这里
ldloc.1 / brfalse.s / ldloc.1 / callvirt / endfinally   ← 外层 finally
```

**假设**：把第二个 `throw` 换成按"识别出的格式"分发的 `switch`。格式值存在某个局部变量里，
取值为 `0..9`。

**验证**：扫描 `ldc.i4.* / stloc.*` 成对位置，找出**被赋过最大常量**的局部变量（本例 9），
则格式数 = 9+1 = 10，且它就是 `switch` 的对象。这样既不写死局部变量号，也不写死格式数。

**重建**：

```
<原样前缀 0x2DA 字节>
ldloc <格式局部变量>            ← 原样字节 ldloc.s 4
switch (10)                    ← case 表由工具计算
br <default>
  0: InstallPackCurseForge   1: InstallPackHMCL     2: InstallPackMMC
  3: InstallPackMCBBS        4: InstallPackModrinth 9: InstallPackLauncherPack
  default: InstallPackCompress
<原样 finally 体>
ldloc.0 / ret                  ← 所有 leave 的目标
```

**为什么能原地替换**：原体的 `leave` 目标都在 `0x2D7`（替换点之前），而"识别成功"是**顺序流入**
`0x2DA` 的——这两点都是验证过的，不是假设。

**异常表迁移**：判据是"哪条子句的 try 区间覆盖了限制桩起点"（而不是 `try offset == 39`），
要求它是 finally 且原 handler 正好指向桩后的 finally 体；三者同时成立才改写
`TryLength` / `HandlerOffset` / `HandlerLength`。

### 4.3 `Save_Click`：给"保存文件"加一段分流

**观察**：条目点击处理器是 `Save_Click`；`Install_Click`（下载到
`<MC 目录>\versions\<名字>\原始整合包.mrpack` → 交给 `ModpackInstall`）完整存在但是死代码。

**假设**：在前面插入

```vb
owner = If(sender Is MyListItem, sender, LateGet(sender, "Parent"))
file  = CType(LateGet(owner, "Tag"), ResourceVersion)
If file.ResourceType = <整合包> Then
    Me.Install_Click(owner, e) : Return
End If
' 以下原逻辑逐字节保留
```

**为什么 `owner` 一定是 `MyListItem`**：`ToListItem` 把处理器挂在 `MyListItem.Click`（sender 就是它），
同时把"另存为"处理器挂在内部 `MyIconButton.Click`（此时 `sender.Parent` 就是 `MyListItem`）。
这就是原方法体里 `isinst + "Parent"` 的来由。

**`<整合包>` 的数值**：`#US` 找 `"整合包"` → 找保存线程（`Save_Click` 里唯一的 `ldftn`）→
在线程体里找作用在 `(ResourceType - 1)` 上的 `switch`（前缀 `ldloc/ldc.i4.1/sub`）→
case 体里 `ldstr "整合包"` 的下标 + 1。若该枚举定义在本程序集内，再从 `Constant` 表读同名
字面量做独立交叉校验，不一致就报错。

**`castclass` 的必要性**：`Install_Click` 的第一个形参是具体类 `PCL.MyListItem`，而 `owner` 来自
`LateGet`（静态类型 `object`）。CLR 校验器不接受把 `object` 直接传给类类型形参——首点即抛
`InvalidProgramException`。所以调用前必须 `castclass`，类型 token 取自**被调方自己的签名 blob**。

**重建**：`<合成前缀>` + `<原方法体逐字节追加>`。前缀是生成的，不依赖原方法体布局。

---

## 5. 重建 IL

### 5.1 就地 vs 搬迁

| 情况 | 手法 | 本例 |
| --- | --- | --- |
| 新体 ≤ 原体 | 原地覆盖 + 清零余量 + 改 `code size` | `LoaderInit`（94 → 51） |
| 新体 > 原体 | 搬迁 + 改 `MethodDef.RVA` | `ModpackInstall`、`Save_Click` |

搬迁目标按规则算出：取 raw 偏移最大的 section（PCL 是 `.reloc`），且要求
`rawPtr + rawSize == fileSize`（否则说明有 overlay，拒绝扩展）。两个新体依次放入同一载体，
第二个按 4 字节对齐。

### 5.2 生成 switch 分发体

所有偏移在生成过程中回填：

```
br 相对偏移 = 目标 - (分支指令偏移 + 指令长度)
switch 表项 = 目标 - (switch 偏移 + 5 + 4*N)
```

生成后立即重解码，要求**每个分支目标都落在指令边界**（或方法末尾）。

### 5.3 异常表迁移

fat 表紧跟 IL（4 字节对齐），每条 24 字节：
`Flags / TryOffset / TryLength / HandlerOffset / HandlerLength / ClassToken`。
只改需要的子句，其余逐字节复制。

### 5.4 签名驱动 `castclass`

读被调方法 `MethodDef.Signature`（blob）→ 解析 calling convention（`0x20` = has this）、
参数个数、返回类型、逐参数类型（`ELEMENT_TYPE_CLASS/VALUETYPE` + TypeDefOrRef）→
取第一个形参 token 作为 `castclass` 目标，并校验两方法的 `EventArgs` 形参是同一 token。

---

## 6. 验证方法论：凭什么说输出是对的

### 6.1 内置 IL 校验器（抽象解释）

- 每个调用的 `(参数个数, 是否有 this, 是否返回值)` **从被调方签名解析**；
- 栈深度逐条模拟，下溢或 `ret` 时非空即报错；
- 栈类型：`ldarg.N` 取自身签名、`castclass/isinst` 覆盖类型，未知记 0；
- 对指定调用（`Install_Click`）**严格**比对实参类型与形参声明类型；
- 分支目标必须在指令边界；
- **不认识的 opcode 一律报错**。

这套校验在实现中抓到过两个真实缺陷（缺 `castclass`、`ldarg.3` 写成 `ldarg.2`）。

### 6.2 落盘前重解析

重新解析输出缓冲区：`LoaderInit` 字节与 code size；`ModpackInstall` 的 RVA / code size /
finally handler 偏移；`Save_Click` 的 RVA / code size / 确实调用了一次 `Install_Click`。

### 6.3 负向测试（校验器不是"永远通过"）

| # | 人为破坏 | 结果 |
| --- | --- | --- |
| 1 | 删 `castclass` | `argument 1 ... declares 0x02000098` |
| 2 | `ldarg.2` → `ldarg.3` | `argument 2 ... declares 0x01000046` |
| 3 | `bne.un.s` 偏移 +1 | `the jump into the original body is misaligned` |
| 4 | 删整合包分流（直接 `ret`） | `the stack is not empty at ret` |
| 5 | 不追加原方法体 | `the original body is misaligned` |
| 6 | 格式数 +1 | **未发现**：IL 仍合法，只是语义错——由推导规则而非校验器保证 |

1、2 正是 2026-10-21 版真实翻车过的两个缺陷。

### 6.4 幂等判据

| 补丁 | 判据 |
| --- | --- |
| `LoaderInit` | 方法体与本工具生成结果逐字节相等 |
| `ModpackInstall` | 限制桩消失，且出现 `switch` 分发 |
| `Save_Click` | 方法体里调用了 `Install_Click` |

---

## 7. 版本适配：PCL 更新后怎么办

先跑 `--probe`（不写文件），对照输出判断属于哪种情况：

| 现象 | 含义 | 处理 |
| --- | --- | --- |
| `method not found: ...` | 类型 / 方法改名或移除 | 反编译确认新名，改 `findType/findMethod` 的字符串 |
| `the restriction stub ... was not found` | 上游换了堵法 | 观察新尾部，改 `analyseModpackInstall()` 的锚点 |
| `the original body has an exception table` | 保存逻辑加了 try/catch | 扩展 `buildSaveClickBody`：连异常表一起平移 |
| `... does not verify: ...` | 重建 IL 不合法 | 看报错里的 `IL_0x...` 与参数序号，通常是签名/类型变了 |

**不需要改代码的情况**：只改版本号 / 资源 / 无关 UI 时，因为方法体长度不再是断言、
`switch` 表与局部变量号与格式数全部重推、`Save_Click` 前缀是重新合成的、枚举值来自
`switch` 而不是写死的 `2`。

仍属**领域知识**、需要人确认的只有两处：case 顺序（0 CurseForge / 1 HMCL / 2 MMC /
3 MCBBS / 4 Modrinth / 末位 LauncherPack / 其余 Compress）与"格式数 = 最大常量 + 1"这条规则。

---

## 8. 从零复刻：步骤清单

1. 读 DOS 头 → `e_lfanew` → PE 头 → Optional Header（`SizeOfImage`、对齐、DataDir[14] = CLI 头）。
2. Section 表 → 建立 `RVA ↔ 文件偏移` 映射。
3. CLI 头 → 元数据根（`BSJB`）→ 5 个堆（`#~`/`#Strings`/`#US`/`#GUID`/`#Blob`）→ 合法表掩码 + 行数数组。
4. 按堆大小标志定堆索引宽度，按"最大行数 + 标签位数"定 coded index 宽度 → 64 张表的行宽与起点。
5. 解析 `TypeDef` / `MethodDef` / `Field` / `TypeRef` / `MemberRef` / `Constant`，建立名称索引。
6. `RVA → 文件偏移`，读方法头（tiny / fat），取出 IL。
7. 写 IL 解码器（§3.4）。
8. `LoaderInit`：抽 token → 生成新体 → 原地写回 + 改 code size（§4.1）。
9. `ModpackInstall`：找桩 / finally / 格式局部变量 → 生成分发体 → 迁移异常表 → 搬迁 → 改 RVA（§4.2）。
10. `Save_Click`：按名称解析 token → 合成前缀 → 追加原体 → 搬迁（§4.3）。
11. 更新 section header（`VirtualSize` / `SizeOfRawData` / `Characteristics = 0x60000020`），
    必要时按 `SectionAlignment` 更新 `SizeOfImage`。
12. 重解析输出逐项校验（§6.2），全部通过才写文件。
13. 用 `--verify` 对输出再跑一遍（应三个 `already patched`），再跑一次补丁应得到**相同字节**。

---

## 9. 目标数据（PCL 2.99.0.0 实测）

> 观测记录，仅用于对照排错；工具本身不依赖这些值。

### 9.1 类型 / 字段

| 名称 | token |
| --- | --- |
| `PCL.PageDownloadInstall` | `0x02000054` |
| `PCL.ModModpack` | `0x0200007E` |
| `PCL.ModDownload` | `0x0200007D` |
| `PCL.PageDownloadResourceDetail` | `0x0200005B` |
| `PCL.ResourceVersion` | `0x02000034` |
| `PCL.MyListItem` | `0x02000098` |
| `PCL.ResourceVersion.ResourceType` | `0x0400008F` |
| `PCL.ModDownload.DlClientListLoader` | `0x0400040F` |

### 9.2 方法

| 方法 | token | 原始 RVA | 原始 code size | 补丁后 |
| --- | --- | --- | --- | --- |
| `LoaderInit` | `0x06000513` | `0x0002DEB4` | `0x5E` | `0x33`（原地） |
| `ModpackInstall(String,String,String)` | `0x060001F0` | `0x00012110` | `0x2EF` | `0x380`（搬迁） |
| `Save_Click(Object,RoutedEventArgs)` | `0x0600068F` | `0x000374F8` | `0x63` | `0xD1`（搬迁） |
| `Install_Click(Object,RoutedEventArgs)` | `0x0600068E` | `0x000371E0` | `0x2EE` | 不变（原本完整） |

### 9.3 补丁用到的 token

| 名称 | token |
| --- | --- |
| `NewLateBinding.LateGet` | `0x0A0000BA` |
| `System.Object`（`newarr` 用） | `0x01000018` |
| `Action::.ctor` | `0x0A00010F`（Save_Click 内）/ `0x0A00058D`（LoaderInit 内） |
| `ModBase.RunInNewThread` | `0x06001143` |
| `_Closure$__24-0::.ctor` / `_Lambda$__0` | `0x060014B9` / `0x060014BA` |
| 七个安装器 | `0x060001F4` … `0x060001FA` |
| 字符串 `"Parent"` / `"Tag"` / `"整合包"` | `0x70011BDE` / `0x70010859` / `0x70047A91` |

`ResourceType` 的枚举类型在外部程序集 `PCLCS.ResourceTypes`（本文件只有 TypeRef），
所以枚举值主要靠 `switch` 表推导：`ResourceType.ModPack = 2`。

---

## 10. 限制与已知问题

1. 只支持 **.NET Framework** 的 PCL（不处理 .NET 5+ 的 ReadyToRun / 单文件）。
2. 不处理强名称签名：改字节会使签名失效（工具不检测也不重签）。
3. `Save_Click` 若出现异常表，当前实现会拒绝（需扩展为"连表一起平移"）。
4. `ModpackInstall` 必须存在唯一的 `ldstr/newobj/throw` 桩；换堵法需按 §7 更新锚点。
5. 枚举值依赖 `switch` 表；若改成字典查表，需换锚点（`Constant` 交叉校验可作备选）。
6. 除目标方法体与 section header 外，工具不修改任何字节（含 `Assembly` 版本、资源）。

**仓库约定**：不提交任何二进制（工具产物、原版 PCL、补丁版 PCL 均在 `.gitignore`）；
文档里的 token / 偏移是观测记录，不是工具输入——工具每次运行都重新推导。
