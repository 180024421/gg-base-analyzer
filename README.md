# gg-base-analyzer

从 **GameGuardian** 导出（生效地址 / 指针搜索结果）分析稳定基址链，导出 **JSON / Frida / Lua**。支持简易 GUI；可选 ADB+Frida 在线向上搜链。

> 仅供学习与研究。请遵守游戏服务条款与当地法律法规。

## 快速开始

```powershell
cd E:\xiangmu\gg-base-analyzer
python -m venv .venv
.\.venv\Scripts\pip install -e ".[dev]"
# 在线搜链（可选）
.\.venv\Scripts\pip install -e ".[online]"
.\一键启动.cmd
```

### CLI

```powershell
# 离线：多份 GG 导出交叉分析
python -m gg_base_analyzer analyze scan1.txt scan2.txt --game mygame --package com.example.game -o .\out

# 在线：已验证地址向上搜链（需 Frida + USB/模拟器）
python -m gg_base_analyzer online-search --package com.example.game --address 0x7E33D6FC --pointer-size 4 -o .\out
```

## 工作流

1. GG 找到「改了界面会动」的地址并导出  
2.（推荐）指针搜索 → 重启后再导 1～2 份  
3. 本工具导入 → 交叉打分 → 导出脚本  

## 文档

- 设计：`docs/superpowers/specs/2026-07-15-gg-base-analyzer-design.md`
- Agent：`AGENTS.md`

## 许可

MIT
