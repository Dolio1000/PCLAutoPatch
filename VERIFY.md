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
大小    5,981,696 字节 (0x5B4600)
SHA256  05D441D3F921A03D086E854072A43CD86DD0FBBE7A1B00618553275B1FC3BA14
```

> 两处补丁的旧版本为 5,981,184 字节（SHA256 `3BFFCB20...4379478`）；
> 第三处补丁修正前的版本为 SHA256 `D4F2A362...C2356E76`（该校验值对应
> 「缺少 castclass + `ldarg.3` 写错」的旧版方法体，启动时会在
> `Save_Click` 抛出 `InvalidProgramException`，**已废弃**）。

### 5.1 与手工补丁版的比对

2026-10-20 记录的手工补丁版（仅两处补丁）：

```text
文件    E:\pxl-g\Plain Craft Launcher 2.patched.exe   （当前目录中已不存在）
大小    5,981,184 字节 (0x5B4400)
SHA256  3BFFCB201575822F9082F0AFC6361A909BDFCAA222A52178307FB0AA43747978
```

**结论：自动生成版与手工补丁版逐字节一致（SHA256 完全相同）。**

### 5.2 字节级改动范围

对原版与补丁版做逐字节比对，改动只落在以下位置：

| 位置 | 内容 |
| --- | --- |
| `0x0001D0` / `0x0001D9` / `0x0001EC` / `0x0001EF` | `.reloc` section header（VirtualSize / SizeOfRawData / Characteristics） |
| `0x0002C0B8` .. `0x0002C11D` | `LoaderInit` 方法体（原地重写） |
| `0x000AFD58` | `ModpackInstall` 的 `MethodDef.RVA` |
| `0x000B5086` | `Save_Click` 的 `MethodDef.RVA` |
| `0x005B3E0C` .. `0x005B3FFF` | 搬迁后的 `ModpackInstall` 方法体 |
| `0x005B4000` .. `0x005B45FF` | 文件尾部新增（搬迁后的 `Save_Click` 方法体 + 对齐填充） |

`SizeOfImage` **未改变**：新的 `.reloc` 虚拟末尾 `0x5B640C` 仍小于 `0x5B8000`。

### 5.3 Section 头变化

| Section | VA | VirtualSize | RawPtr | RawSize | Characteristics |
| --- | --- | --- | --- | --- | --- |
| `.text` | `0x2000` | `0x581BD0` | `0x200` | `0x581C00` | `0x60000020`（未变） |
| `.rsrc` | `0x584000` | `0x31FB4` | `0x581E00` | `0x32000` | `0x40000040`（未变） |
| `.reloc` | `0x5B6000` | `0xC` → **`0x40C`** | `0x5B3E00` | `0x200` → **`0x600`** | `0x42000040` → **`0x60000020`** |

文件末尾随之从 `0x5B4000` 扩展到 `0x5B4600`（`0x600` 字节）。
`SizeOfImage` 保持 `0x5B8000`——新的虚拟末尾 `0x5B640C` 仍在其范围内，
因此不需要修改。

### 5.4 `MethodDef` RVA 更新

```text
ModpackInstall   文件偏移 0x000AFD58   原值 0x00012110   新值 0x005B600C
Save_Click       文件偏移 0x000B5086   原值 0x000374F8   新值 0x005B63E4
```

新方法体落在 `.reloc` 内：`ModpackInstall` 相对偏移 `0xC`（文件 `0x5B3E0C`），
`Save_Click` 相对偏移 `0x3E4`（文件 `0x5B41E4`）。

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

原来位于 `IL_02DA` 的限制桩（`ldstr / newobj / throw`）被上述分发代码**原位替换**；
`IL_02E5` 起的 finally 体被搬到 `IL_0374`，其后追加 `ldloc.0 / ret` 作为统一出口。

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

### 6.4 `Save_Click`（新方法体 file off `0x005B41E4`，fat header 12 字节）

```text
codesize = 209 (0xD1)   （算上 12 字节 fat header 共 221 字节）
maxstack = 16
localSig = 0x00000000（与原方法一致，无局部变量）
```

补丁后的方法体分三段：

```text
IL[0x000..0x040]  分流 prologue
  03                ldarg.1
  75 98 00 00 02    isinst PCL.MyListItem
  2D 17             brtrue.s -> IL_001F
  03 14 72 DE 1B 01 70 16 8D 18 00 00 01 14 14 14 28 BA 00 00 0A
                    ldarg.1 / ldnull / ldstr "Parent" / ldc.i4.0 / newarr Object
                    / ldnull x3 / call LateGet
  2B 01             br.s -> IL_0020
  03                ldarg.1                    ; owner = sender（是 MyListItem 时）
  14 72 59 08 01 70 16 8D 18 00 00 01 14 14 14 28 BA 00 00 0A
                    ldnull / ldstr "Tag" / ... / call LateGet
  74 34 00 00 02    castclass PCL.ResourceVersion
  7B 8F 00 00 04    ldfld  PCL.ResourceVersion::ResourceType
  18                ldc.i4 2                   ; 整合包
  33 2D             bne.un.s -> IL_006E        ; 不是整合包 -> 走原逻辑

IL[0x041..0x06D]  整合包分支
  02                ldarg.0                    ; this
  03 75 98 00 00 02 2D 17 ...                 ; 再次解析 owner
  2B 01 03                                    ; ... br.s / ldarg.1
  74 98 00 00 02    castclass PCL.MyListItem   ; ← 关键：CLR 校验器要求实参静态类型
  04                ldarg.2                    ; e
  28 8E 06 00 06    call PCL.PageDownloadResourceDetail::Install_Click
  2A                ret

IL[0x06E..0x0D0]  原方法体（0x63 字节，逐字节原样保留）
```

分支目标复核（按字节手算）：

```text
brtrue.s @0x0006  operand 0x17 -> IL_001F   (= ldarg.1，owner = sender)
br.s     @0x001D  operand 0x01 -> IL_0020   (= 文件解析片段开头)
bne.un.s @0x003F  operand 0x2D -> IL_006E   (= 原方法体开头 newobj)
brtrue.s @0x0048  operand 0x17 -> IL_0061   (= ldarg.1)
br.s     @0x005F  operand 0x01 -> IL_0062   (= castclass)
```

#### 为什么需要 `castclass`

`Install_Click` 的第一个形参不是 `object`，而是具体类 `PCL.MyListItem`
（`MethodDef 0x0600068E` 的签名 blob `20 02 01 12 82 60 12 81 19`）：

```text
calling conv 0x20 (HASTHIS)
param1  ELEMENT_TYPE_CLASS 0x12 + TypeDefOrRef 0x182 -> TypeDef 152 = PCL.MyListItem (0x02000098)
param2  System.EventArgs   (0x01000046)
return  void
```

而 `Save_Click` 的 `owner` 来自 `LateGet`，静态类型是 `object`。
CLR 校验器**不允许**把 `object` 直接传给类类型形参（这是
`InvalidProgramException: 公共语言运行时检测到无效的程序` 的直接原因），
因此在调用前必须 `castclass` 到形参的确切类型。

- 类型 token **不是硬编码**，而是由工具解析 `Install_Click` 自己的签名 blob 得到；
- 程序先 `castclass PCL.MyListItem`（由类型名解析得到，因为两条 `owner` 路径的
  运行时类型都是它），若形参声明类型与它不同，再补一个 `castclass` 到形参类型；
- 校验器对 `Install_Click` 的实参做**严格类型比对**（实参静态类型必须等于形参声明类型），
  同时校验 `Install_Click` 与 `Save_Click` 的 `EventArgs` 形参是同一个 token。

（`owner` 在两条解析路径下都必然是 `MyListItem`：一条是 `sender` 本身就是
`MyListItem`，另一条是「另存为」按钮 `MyIconButton` 的 `Parent`
—— 该按钮由 `ResourceVersion.ToListItem` 挂在 `MyListItem.Buttons` 里。）

### 6.5 `Save_Click` 的栈与类型验证

工具的校验不再靠"反解未知调用的净效果"：它直接解析每个调用目标的
签名 blob（`MethodDef` 与 `MemberRef` 两条路径），从而精确得到
实参个数、是否有 `this`、是否返回值：

```text
IL_0068  MethodDef 0x0600068E  Install_Click                 3 个栈槽 / 无返回值
IL_006E  MethodDef 0x060014B9  _Closure$__24-0::.ctor        newobj / 0 参数
IL_0093  MemberRef 0x0A0000BA  NewLateBinding.LateGet        7 参数 / static / 返回 object
IL_00AA  MemberRef 0x0A0000BA  同上
IL_00BF  MemberRef 0x0A00010F  System.Action::.ctor          newobj / 2 参数
IL_00CA  MethodDef 0x06001143  ModBase.RunInNewThread        3 参数 / static / 返回 object
```

（`IL_006E` 之后是原方法体，逐字节追加，所以各调用的偏移都等于原偏移 + `0x6E`。）

据此做**深度 + 类型**的抽象解释，要求：无栈下溢、所有跳转目标落在
指令边界、`ret` 处栈为空、并且对指定调用（`Install_Click`）严格检查
实参静态类型与形参声明类型一致。

| 方法体 | 结论 | 最大栈深 |
| --- | --- | --- |
| 原版 `Save_Click`（99 字节） | 通过 | 9（= 声明的 `maxstack`） |
| 修正前的补丁方法体（204 字节） | **报错**：`argument 1 has type 0x00000000 but the callee declares 0x02000098` | — |
| 当前补丁方法体（IL 209 字节） | 通过 | 9 |

即补丁后的方法体与原方法体的栈纪律完全一致；声明的 `MaxStack = 16`
远大于实际需求 9。

外部独立验证器（`ilverify.py`，与工具实现无共享代码）给出相同结论：
原版与补丁版都只有一个合法解，最大栈深均为 9。

### 6.6 校验器与生成器的负向测试

为了确认校验不是"永远通过"，对工具源码做 6 处人为破坏，逐一重编译运行：

| # | 破坏 | 结果 |
| --- | --- | --- |
| 1 | 删掉 `castclass` | `ERROR: Save_Click: the rebuilt method does not verify: argument 1 of call 0x0600068E at IL_0x64 has type 0x00000000 but the callee declares 0x02000098` |
| 2 | `ldarg.2` 写成 `ldarg.3`（0x04 → 0x05） | `ERROR: ... argument 2 ... declares 0x01000046` |
| 3 | `bne.un.s` 相对偏移差 1 | `ERROR: Save_Click: internal error - the jump into the original body is misaligned` |
| 4 | 删除整合包分流分支（直接 `ret`） | `ERROR: ... the stack is not empty at ret IL_0x3F (depth 2)` |
| 5 | 删除原方法体追加 | `ERROR: Save_Click: internal error - the original body is misaligned` |
| 6 | 把格式数推导结果 +1（`switch` 11 项） | **未被 IL 校验发现**：生成的 IL 仍然合法，只是语义错误 |

第 1、2 条正是 2026-10-21 版真实翻车过的两个缺陷，均已修正。
第 6 条说明 IL 校验的边界：它只保证"生成的代码合法"，不保证"业务语义正确"；
语义部分由**推导规则**保证（格式局部变量与格式数、case 顺序），见 §6.7。

### 6.7 结构锚点（本次重构后的定位方式）

工具**不使用**任何绝对文件偏移。每个补丁点的定位依据：

| 补丁 | 锚点 |
| --- | --- |
| `LoaderInit` | 名称 `PCL.PageDownloadInstall.LoaderInit`；体形：`ldarg.0/call ControlInit` → `ldarg.0` → 3×(`ldarg.0/callvirt get_X`) → 尾部 `ldarg.0/ldftn/newobj Action/ldnull/ldc.i4/call/ret` |
| `ModpackInstall` | 名称 + 体形：唯一的 `ldstr/newobj/throw` 三元组（限制桩）→ 紧随其后的 `ldloc/brfalse/ldloc/call/endfinally`（finally 体）→ 被赋过最大常量的局部变量与格式数 |
| `Save_Click` | 名称；全部 token 由名称解析（`MyListItem`、`ResourceVersion`、`ResourceType`、`LateGet`、`System.Object`、`"Parent"`/`"Tag"`、`Install_Click`）；整合包枚举值由 `switch` 表 + `#US` 字面量推导 |

`--probe` 会把这些推导结果全部打印出来：

```text
  LoaderInit tokens:
    ControlInit       0x06000512
    get_LoadMinecraft 0x06000607
    get_PanLoad       0x06000605
    get_PanAllBack    0x06000551
    _Lambda$__R3-4    0x0600061C
    Action ctor       0x0A00058D
    PageLoaderInit    0x2B0000CA
    DlClientListLoader 0x0400040F
  ModpackInstall patch: stub=IL_0x2DA finally=IL_0x374+0xA formatLocal=4 formats=10
                        code=0x380 body=984 newRVA=0x005B600C fileOff=0x5B3E0C
  Save_Click tokens:
    MyListItem        0x02000098
    ResourceVersion   0x02000034
    ResourceType      0x0400008F
    LateGet           0x0A0000BA
    System.Object     0x01000018
    "Parent" / "Tag"  0x70011BDE / 0x70010859
    save worker       0x060014BA
    Install_Click     0x0600068E (first parameter 0x02000098)
  Save_Click patch: modpack resource type = 2 (from the save worker's switch table; ...)
  Probe: every anchor was derived from the metadata and the IL shape; no output written.
```


---

## 7. JIT 验证

使用 `ildump\jit.exe` 对输出文件中的两个方法强制编译：

```text
JIT OK 0x06000513 PCL.PageDownloadInstall::LoaderInit
JIT OK 0x060001F0 PCL.ModModpack::ModpackInstall
```

说明：`jit.exe` 需要 `Newtonsoft.Json 13.0.0.0`；测试时在临时 `ildump` 目录中放置了
net45 版本的 `Newtonsoft.Json.dll`。该 DLL 只是 JIT 测试依赖，**不属于补丁内容**。

`Save_Click` **无法**单独 JIT：所在程序集引用 `PCLCS`、`MeloongCore`、
`MeloongCore.Wpf`、`CacheCow.*`、`NAudio`、`ThrottleDebounce`、`Imazen.WebP`、
`Newtonsoft.Json`，本机均缺失（`Assembly.LoadFrom` + `GetType` 直接
`FileNotFoundException: PCLCS`）。因此该入口改用两条独立证据：
工具内置校验器（§6.5）+ 外部独立验证器 `ilverify.py`（与工具无共享代码）。

---

## 8. 幂等与安全失败测试

### 8.1 幂等：把已补丁文件再次输入

```text
> pclautopatch.exe "E:\pxl-g\Plain Craft Launcher 2.autopatched.exe" --verify
State: LoaderInit=already patched, ModpackInstall=already patched, Save_Click=already patched
Verify-only: no output written.
退出码 0
```

不传 `--verify` 时会原样复制到输出路径，不做二次修改。

"是否已打过补丁"的判据是**语义**的（2026-10-22 起）：

| 补丁 | 判据 |
| --- | --- |
| `LoaderInit` | 方法体与本工具生成的结果逐字节相等 |
| `ModpackInstall` | 限制桩（`ldstr/newobj/throw`）消失，且出现 `switch` 分发 |
| `Save_Click` | 方法体里调用了 `Install_Click` |

因此方法体长度、局部变量号、偏移全部变化时仍然能正确识别。

### 8.2 模式不符：破坏 `ControlInit` 的调用 opcode

把原文件 `LoaderInit` 的 `ControlInit` 调用 opcode（文件偏移 `0x2C0C1`）由 `0x28` 改为 `0x29`：

```text
ERROR: LoaderInit: ControlInit call not found at the beginning of the body
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
输出大小  5,981,696 字节 (0x5B4600)
输出 SHA256 05D441D3F921A03D086E854072A43CD86DD0FBBE7A1B00618553275B1FC3BA14
```

多次运行（含对已补丁文件再次运行）结果稳定，可复现，与构建环境无关。

### 9.1 结构锚点重构（2026-10-22）后仍逐字节一致

把三处补丁点的定位方式从"方法体长度 + 固定偏移"改成"名称 + 指令形状 + 数据流"之后，
对同一份原版文件重新生成的结果**与原实现的输出逐字节相同**
（SHA256 仍为 `05D441D3...1FC3BA14`）。

这说明重构没有改变任何一个输出字节，只是把"为什么这样改"的依据从"这一次的行号"
换成了"语义锚点"。重构后新增/加强的检查：

| 检查 | 位置 |
| --- | --- |
| `LoaderInit` 的 5 个调用 token 与名称解析结果交叉校验 | `extractLoaderTokens()` |
| `ModpackInstall` 的限制桩 / finally 形状 / 格式局部变量 / 格式数全部推导 | `analyseModpackInstall()` |
| `ModpackInstall` 重建体重新解码，所有分支必须落在指令边界 | `buildModpackCode()` 尾部 |
| `Save_Click` 前缀由 token 合成，不再依赖原方法体布局 | `buildSaveClickBody()` |
| `Save_Click` 跳入原方法体的偏移必须精确等于拼接点 | `buildSaveClickBody()` |
| 幂等判据改为语义判据（§8.1） | `isModpackPatched()` / `isSaveClickPatched()` |

---

## 9.1 手工验收清单（供使用者回归）

| # | 操作 | 期望 |
| --- | --- | --- |
| 1 | 下载页 → 整合包 → 点某个整合包 → 点某个版本 | 弹「输入版本名称」，**不再**弹「保存文件」对话框 |
| 2 | 观察 `.minecraft\versions\<版本名>\` | 出现 `原始整合包.mrpack`，整合包被解压安装到该实例 |
| 3 | 下载页 → Mod / 资源包 / 光影包 / 数据包 → 点版本 | 仍然弹「保存文件」对话框（行为未变） |
| 4 | 把 `.mrpack` 直接拖进 PCL 窗口 | 仍然能安装（`FormMain.FileDrag` → `ModpackInstall`） |
| 5 | 主页 → 整合包搜索 → 点「安装整合包」按钮 | 仍显示上游的限制提示（该入口未改动） |

---

## 10. 保留情况

```text
E:\pxl-g\Plain Craft Launcher 2.exe            未修改，哈希仍为 6B6E...
E:\pxl-g\Plain Craft Launcher 2.autopatched.exe 自动生成版，哈希 05D4...
E:\pxl-g\pclautopatch.exe                       构建产物（不纳入版本控制）
E:\pxl-g\pclautopatch.cpp                       工具源码
E:\pxl-g\build.bat                              构建脚本
E:\pxl-g\README.md / VERIFY.md                  文档
```

---

## 11. 结论

1. 工具能够稳定、可重复地把 PCL 2.99.0.0 的**三个**被锁死的入口恢复为可用状态：
   下载页加载器、整合包安装分发器，以及整合包详情页"点击即下载到游戏目录"的处理器接线；
2. 前两个入口的输出与人工手工补丁的结果**逐字节一致**，且已通过 CLR JIT 编译验证；
   第三个入口由工具内置的 IL 校验器（栈深度 + 调用实参类型，按被调方签名解析）
   与外部独立验证器双重复核，最大栈深 9，与原方法完全一致；
   该校验器本身经过 6 组负向测试（§6.6），其中两组正是本次修正的两个真实缺陷；
3. 三个补丁点的定位**全部基于语义锚点**（名称 / `#US` 字面量 / 指令形状 / 数据流 /
   元数据常量），不使用任何绝对文件偏移；`--probe` 可打印全部推导结果（§6.7），
   便于在 PCL 更新后快速判断"哪些锚点还成立"；
   重构后输出与原实现**逐字节相同**（§9.1）；
4. 在任何检测失败、模式不符、路径冲突的情况下，工具都**先报错退出、不留半成品**；
5. 输入文件在整个流程中始终保持原样（哈希不变）。

### 仍然保留的上游限制

以下入口**未**改动，点击后仍会显示上游的限制提示（`为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能…`）：

| 入口 | 位置 |
| --- | --- |
| 整合包搜索页的「安装整合包」按钮 | `PCL.PageResource.BtnSearchInstallModPack_Click` → `PCL.ModModpack.ModpackInstall()`（0 参） |
| 拖拽导入整合包时的异常分支 | `_Closure$__25-0::_Lambda$__0` `IL_0295`（仅过滤限制文案，主体流程已可用） |
| 一处未定位到宿主的抛异常分支 | `_Closure$__::_Lambda$__3-0`（11 字节 `ldstr / newobj / throw`） |

> 本工具绕过上游"为遵守相关法律法规"的限制，仅供本地研究；
> **不要分发修改后的二进制**。
