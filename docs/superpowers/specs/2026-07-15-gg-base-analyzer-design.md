# gg-base-analyzer 设计规格

日期：2026-07-15  
状态：已确认（2026-07-15）  
方案：混合分期（方案 3）— 一期离线分析 + GUI；二期 ADB/Frida 在线搜链一并交付  
确认项：路径 `E:\xiangmu\gg-base-analyzer`；需美观 GUI；JSON+Frida+Lua；P2 本期实现；独立远程仓库

## 1. 目标

用户在 GameGuardian（GG）中自行确认「修改后界面会动」的数值地址后，将 **生效地址** 与/或 **指针搜索结果** 导出；本工具解析这些导出，筛出稳定基址链，并生成可在脚本中使用的配置与读内存代码。

不替代 GG 内的「找值 / 验证生效」步骤；不依赖 Cheat Engine 宿主进程。

与 `ce-base-extractor` 的关系：独立仓库，可借鉴其交叉验证 / 打分 / 导出思路，**不** import、不依赖 ce-base 包。

## 2. 成功标准

一期（MVP）满足：

1. 能解析至少一种 GG「地址列表」文本导出，以及一种「指针路径」文本导出（格式可按用户样例迭代）。
2. 导入 2～3 份「重启后再次导出」的指针结果时，能做交叉过滤，优先保留多次均出现的链。
3. 打分时优先 `libil2cpp.so` / `libunity.so` / 游戏常见 `.so`；纯匿名堆链降权但不一定丢弃。
4. 导出：`chains.json` + Frida guest 脚本 + Lua 读链片段（ASS 友好）。
5. CLI 可跑通；可选简易 Tk GUI（拖入文件 → 分析 → 导出）。
6. 单测不依赖真机 / 模拟器；用 fixture 文本覆盖解析与交叉逻辑。

二期满足：

7. 仅提供已验证地址 + Android 包名时，可通过 ADB + Frida（或 process memory 可读接口）在客体内向上搜指针，输出候选链后再走同一套打分 / 交叉 / 导出。

## 3. 非目标（明确不做）

- 自动修改游戏数值、绕过商业反作弊、提供开箱即用的「一键改金币」。
- 解析 CE 的 `.sqlite` / `.PTR`（那是 ce-base 的职责）。
- 一期实现完整在线搜链。
- 保证兼容所有第三方「汉化 / 魔改」GG 导出格式；以官方 GG 导出为准，特殊格式按样例增量适配。

## 4. 用户工作流

### 4.1 一期（离线）

```text
GG 找值 → 确认改界面会动
  → 导出「生效地址」列表（可选）
  → GG 指针搜索 → 导出路径（建议重启游戏后再搜/再导 1～2 份）
  → gg-base-analyzer 导入 1～N 个文件
  → 交叉 + 打分 → 选出稳定链
  → 设置字段名 / 类型 → 导出 JSON / Frida / Lua
```

### 4.2 二期（在线，可选增强）

```text
用户提供：包名 + 已验证地址（hex）
  → 工具 attach（Frida）→ 模块枚举 + 向上指针搜索
  → 产出与一期相同的 PointerChain 列表
  → 仍建议用户重启后再跑一次做交叉
```

## 5. 输入格式（一期）

GG 各版本导出措辞略有差异。一期采用「宽松解析 + 样例驱动」：

| 输入类型 | 期望信息 | 解析策略 |
|----------|----------|----------|
| 地址列表 | 绝对地址、可选类型/数值/备注 | 识别 `0x...` / 十进制地址行；忽略无法识别行并记 warning |
| 指针搜索结果 | 路径：模块名+偏移 或 绝对基址 + 多级 offset | 识别 `libXXX.so`、`:`/`+`/`->` 分隔的 offset；匿名基记为 `[anon]` 或空模块 |
| 手工 JSON（工具自有） | 规范 schema | 工具也可输出再回读，便于二轮交叉 |

示例（规范内部表示，非 GG 原文）：

```json
{
  "kind": "pointer_paths",
  "package": "com.example.game",
  "paths": [
    {
      "module": "libil2cpp.so",
      "module_offset": "0xA1B2C0",
      "offsets": ["0x18", "0xA0"],
      "value_type": "int32",
      "field_name": "gold"
    }
  ]
}
```

安装 GG 并完成首次导出后，用真实样例增补 `parsers/gg_text.py` 的规则；规格层要求「未知行可跳过，不能因一行坏数据整文件失败」。

## 6. 核心模型

```text
PointerChain
  module_name: str          # e.g. libil2cpp.so；匿名为空或 "[anon]"
  module_offset: int
  offsets: tuple[int, ...]
  score: float
  source: str               # 来源文件 / online
  field_name: str
  value_type: str           # int32 | int64 | float | ...
  verified: bool            # 用户标记「改了会动」关联

AddressHit
  address: int
  value_type: str
  note: str
```

交叉键（稳定身份）：

- 精确：`(module_lower, module_offset, offsets)`
- 模糊（可选）：末级 offset 按步长容差（对齐 ce-base fuzzy 思路）

## 7. 分析管线

```text
load_files → normalize_chains
  → (optional) filter by module whitelist/blacklist, max_depth, max_offset
  → cross_validate if N>=2 else score_single
  → rank / top_n
  → attach field names from address list notes if any
  → export
```

打分启发（一期）：

- 落在 prefer 模块（il2cpp/unity/main）加权
- 深度越小越好
- 单级 offset 过大降权
- 交叉命中次数（2/2、3/3）为最高优先级信号

## 8. 导出

| 产物 | 用途 |
|------|------|
| `*_chains.json` | 规范配置，给脚本 / 二轮分析 |
| `*_frida.js` | 客体内 `Module.findBaseAddress` + 读链 |
| `*_read.lua` | Auto Script Studio / 通用 Lua 读链模板 |
| `*_report.txt` | 人读：稳定率、候选列表、警告 |

## 9. 仓库结构（拟定）

```text
gg-base-analyzer/
  README.md
  AGENTS.md
  pyproject.toml
  requirements.txt
  gg_base_analyzer/
    __init__.py
    __main__.py
    models.py
    pipeline.py
    parsers/
      gg_text.py          # 宽松文本解析
      gg_json.py          # 自有 JSON
    filters/
      scorer.py
      cross_validate.py
    export/
      json_export.py
      frida_script.py
      lua_script.py
      report.py
    online/               # 二期
      frida_search.py
      adb.py
    gui/
      app.py              # 可选简易 Tk
  tests/
    fixtures/             # 合成 / 脱敏 GG 样例
    test_parsers.py
    test_cross.py
    test_export.py
  docs/
    superpowers/
      specs/
        2026-07-15-gg-base-analyzer-design.md
    GUIDE.md              # GG 导出怎么点（用户文档）
```

技术栈：Python 3.11+，标准库优先；GUI 用 tkinter；二期 Frida 为可选依赖。

## 10. CLI 草图

```powershell
# 一期：多文件交叉 + 全量导出
python -m gg_base_analyzer analyze path1.txt path2.txt `
  --game mygame --package com.example.game -o ./out

# 仅规范化并打分（单文件）
python -m gg_base_analyzer analyze scan.txt --top 30 -o ./out

# 二期
python -m gg_base_analyzer online-search `
  --package com.example.game --address 0x7E33D6FC --pointer-size 4
```

## 11. 分期计划

| 阶段 | 内容 | 完成定义 |
|------|------|----------|
| **P1a** | 项目骨架、模型、合成 fixture、文本/JSON 解析、单文件打分、JSON 导出 | pytest 绿；CLI analyze 可读 fixture |
| **P1b** | 交叉验证、Frida/Lua/report 导出、README + GUIDE | 多文件 analyze 出稳定链 |
| **P1c** | 简易 GUI（可选）、按真实 GG 样例修解析 | 用户拖入真实导出可跑 |
| **P2** | ADB 检测、Frida 向上搜链、结果并入同一 pipeline | online-search 产出可被 analyze 消费的 JSON |

默认交付顺序：P1a → P1b →（有真实样例后）P1c → P2。

## 12. 风险与缓解

| 风险 | 缓解 |
|------|------|
| GG 导出格式不一 | 宽松解析 + 样例回归；支持工具自有 JSON 作稳定交换格式 |
| 指针结果全是匿名堆 | 报告明确提示「重启交叉」；优先模块链；二期结合模块边界搜 |
| 用户把「仅地址」当基址 | UI/CLI 说明：单地址不能当基址；需指针导出或等 P2 |
| Frida 被游戏检测（P2） | 文档标明限制；失败时回退离线流程 |

## 13. 许可与合规

MIT（拟定）。仅供学习与研究；文档声明遵守游戏服务条款与当地法律。不提供针对特定商业游戏的现成作弊配置。

## 14. 确认结论（2026-07-15）

1. 路径：`E:\xiangmu\gg-base-analyzer` — OK  
2. GUI：需要，深色青绿主题  
3. 导出：JSON + Frida + Lua 全部要  
4. P2：本期一并实现  
5. 独立远程 GitHub 仓库  
