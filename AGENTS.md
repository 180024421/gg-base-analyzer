# AGENTS.md — gg-base-analyzer

独立工具：GameGuardian 导出 → 稳定基址链 → JSON/Frida/Lua。不依赖 ce-base-extractor。

## 模块

| 模块 | 路径 | 职责 |
|------|------|------|
| 模型 | `models.py` | PointerChain / AddressHit / AnalyzeConfig |
| 解析 | `parsers/` | GG 文本 / 自有 JSON |
| 过滤 | `filters/` | 打分、交叉验证 |
| 导出 | `export/` | JSON / Frida / Lua / 报告 |
| 在线 | `online/` | ADB、Frida 向上搜链（可选依赖） |
| GUI | `gui/` | Tk 主界面 |
| 流水线 | `pipeline.py` | analyze / online 入口 |

## 约定

- 用户数据：`%USERPROFILE%\Documents\gg-base-analyzer\`
- 在线功能：`frida` 未安装时 CLI/GUI 明确提示，不崩溃
- 测试：不依赖真机；`tests/fixtures/` 合成样例

## 命令

```powershell
pytest tests -q
ruff check .
python -m gg_base_analyzer gui
```
