from __future__ import annotations

import argparse
import sys
from pathlib import Path

from gg_base_analyzer.export import export_all
from gg_base_analyzer.filters import filter_and_rank
from gg_base_analyzer.models import AnalyzeConfig, AnalyzeResult
from gg_base_analyzer.online import frida_available, online_search_chains
from gg_base_analyzer.pipeline import analyze_files


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gg-base-analyzer",
        description="GameGuardian 导出 → 稳定基址 → JSON/Frida/Lua",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="离线分析 GG 导出文件")
    a.add_argument("inputs", nargs="+", help="GG 文本/JSON 导出，可多个做交叉")
    a.add_argument("--game", default="game")
    a.add_argument("--package", default="")
    a.add_argument("-o", "--output", default="./gg_out")
    a.add_argument("--top", type=int, default=30)
    a.add_argument("--cross-min", type=int, default=2)
    a.add_argument("--pointer-size", type=int, choices=(4, 8), default=4)
    a.add_argument("--require-all", action="store_true")

    o = sub.add_parser("online-search", help="Frida 在线向上搜链（可选）")
    o.add_argument("--package", required=True)
    o.add_argument("--address", required=True, help="已验证生效地址，如 0x7E33D6FC")
    o.add_argument("--game", default="game")
    o.add_argument("-o", "--output", default="./gg_out")
    o.add_argument("--pointer-size", type=int, choices=(4, 8), default=4)
    o.add_argument("--device", default=None, help="Frida device id")
    o.add_argument("--spawn", action="store_true")
    o.add_argument("--top", type=int, default=30)

    sub.add_parser("gui", help="打开图形界面")
    return p


def _cfg_from_analyze(args) -> AnalyzeConfig:
    return AnalyzeConfig(
        game_name=args.game,
        android_package=args.package,
        top_n=args.top,
        cross_min=args.cross_min,
        pointer_size=args.pointer_size,
        require_all=args.require_all,
    ).validate()


def cmd_analyze(args) -> int:
    cfg = _cfg_from_analyze(args)
    result = analyze_files(args.inputs, cfg, export_dir=args.output)
    print(f"模式: {result.meta.get('mode')}  链: {len(result.chains)}  地址: {len(result.addresses)}")
    for w in result.warnings[:20]:
        print(f"警告: {w}")
    for i, c in enumerate(result.chains[:15], 1):
        print(f"  {i:02d}. [{c.score:5.1f}] {c.display()}")
    print(f"已导出 → {args.output}")
    return 0


def cmd_online(args) -> int:
    if not frida_available():
        print("错误: 未安装 frida。请执行: pip install -e \".[online]\"", file=sys.stderr)
        return 2
    addr = int(args.address, 0)
    cfg = AnalyzeConfig(
        game_name=args.game,
        android_package=args.package,
        pointer_size=args.pointer_size,
        top_n=args.top,
    ).validate()
    try:
        chains = online_search_chains(
            args.package,
            addr,
            cfg,
            device_id=args.device,
            spawn=args.spawn,
        )
    except Exception as e:
        print(f"在线搜索失败: {e}", file=sys.stderr)
        return 1
    ranked = filter_and_rank(chains, cfg)
    result = AnalyzeResult(
        chains=ranked,
        meta={"mode": "online", "address": hex(addr), "raw": len(chains)},
        warnings=[] if ranked else ["未找到候选，请确认地址仍有效且进程已附加"],
    )
    files = export_all(result, args.output, game=cfg.game_name, package=args.package)
    print(f"候选原始 {len(chains)} → 排名后 {len(ranked)}")
    for i, c in enumerate(ranked[:15], 1):
        print(f"  {i:02d}. [{c.score:5.1f}] {c.display()}")
    print("导出:")
    for f in files:
        print(f"  {f}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "analyze":
        return cmd_analyze(args)
    if args.cmd == "online-search":
        return cmd_online(args)
    if args.cmd == "gui":
        from gg_base_analyzer.gui.app import run_app

        run_app()
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
