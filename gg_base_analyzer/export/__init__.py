from __future__ import annotations

from pathlib import Path

from gg_base_analyzer.export.frida_script import save_frida_script
from gg_base_analyzer.export.json_export import save_chains_json
from gg_base_analyzer.export.lua_script import save_lua_script
from gg_base_analyzer.export.report import save_report
from gg_base_analyzer.models import AnalyzeResult


def export_all(
    result: AnalyzeResult,
    out_dir: str | Path,
    *,
    game: str = "game",
    package: str = "com.example.game",
) -> list[Path]:
    folder = Path(out_dir)
    folder.mkdir(parents=True, exist_ok=True)
    stem = game or "game"
    files = [
        save_chains_json(result, folder / f"{stem}_chains.json", game=game, package=package),
        save_frida_script(result, folder / f"{stem}_frida.js", package=package),
        save_lua_script(result, folder / f"{stem}_read.lua", game=game),
        save_report(result, folder / f"{stem}_report.txt", game=game),
    ]
    return files
