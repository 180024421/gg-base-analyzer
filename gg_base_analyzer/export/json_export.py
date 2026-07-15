from __future__ import annotations

import json
from pathlib import Path

from gg_base_analyzer.models import AnalyzeResult, PointerChain


def result_to_dict(result: AnalyzeResult, *, game: str = "", package: str = "") -> dict:
    return {
        "kind": "pointer_paths",
        "game": game,
        "package": package,
        "meta": result.meta,
        "warnings": result.warnings,
        "addresses": [
            {
                "address": f"0x{a.address:X}",
                "value_type": a.value_type,
                "note": a.note,
                "value": a.value,
            }
            for a in result.addresses
        ],
        "paths": [
            {
                "name": c.export_name(i),
                "module": c.module_name,
                "module_offset": f"0x{c.module_offset:X}",
                "offsets": [f"0x{o:X}" for o in c.offsets],
                "value_type": c.value_type,
                "score": round(c.score, 2),
                "source": c.source,
                "display": c.display(),
            }
            for i, c in enumerate(result.chains, 1)
        ],
    }


def save_chains_json(
    result: AnalyzeResult,
    output: str | Path,
    *,
    game: str = "",
    package: str = "",
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result_to_dict(result, game=game, package=package), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path
