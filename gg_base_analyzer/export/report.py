from __future__ import annotations

from pathlib import Path

from gg_base_analyzer.models import AnalyzeResult


def result_to_report(result: AnalyzeResult, *, game: str = "") -> str:
    lines = [
        "gg-base-analyzer report",
        f"game: {game or '-'}",
        f"chains: {len(result.chains)}",
        f"addresses: {len(result.addresses)}",
        f"meta: {result.meta}",
        "",
        "== chains ==",
    ]
    for i, c in enumerate(result.chains, 1):
        lines.append(
            f"{i:02d}. [{c.score:6.1f}] {c.export_name(i):16s} {c.display()}  ({c.source})"
        )
    if result.addresses:
        lines.append("")
        lines.append("== addresses ==")
        for a in result.addresses:
            lines.append(f"  0x{a.address:X}  {a.value_type}  {a.note}")
    if result.warnings:
        lines.append("")
        lines.append("== warnings ==")
        for w in result.warnings:
            lines.append(f"  - {w}")
    lines.append("")
    return "\n".join(lines)


def save_report(result: AnalyzeResult, output: str | Path, *, game: str = "") -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result_to_report(result, game=game), encoding="utf-8")
    return path
