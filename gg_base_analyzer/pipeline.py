from __future__ import annotations

from pathlib import Path

from gg_base_analyzer.export import export_all
from gg_base_analyzer.filters import cross_validate, filter_and_rank
from gg_base_analyzer.models import AddressHit, AnalyzeConfig, AnalyzeResult, PointerChain
from gg_base_analyzer.parsers import load_gg_file, load_gg_json


def _load_one(path: Path) -> tuple[list[PointerChain], list[AddressHit], list[str]]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return load_gg_json(path)
    return load_gg_file(path)


def analyze_files(
    paths: list[str | Path],
    cfg: AnalyzeConfig | None = None,
    *,
    export_dir: str | Path | None = None,
) -> AnalyzeResult:
    cfg = (cfg or AnalyzeConfig()).validate()
    file_chains: list[list[PointerChain]] = []
    all_addresses: list[AddressHit] = []
    warnings: list[str] = []
    seen_addr: set[int] = set()

    for raw in paths:
        path = Path(raw)
        if not path.exists():
            warnings.append(f"文件不存在: {path}")
            continue
        chains, addresses, warns = _load_one(path)
        warnings.extend(warns)
        file_chains.append(chains)
        for a in addresses:
            if a.address not in seen_addr:
                seen_addr.add(a.address)
                all_addresses.append(a)

    if not file_chains:
        return AnalyzeResult(warnings=warnings or ["没有可读的输入文件"])

    non_empty = [c for c in file_chains if c]
    meta: dict = {"input_files": [str(Path(p)) for p in paths]}

    if len(non_empty) >= cfg.cross_min:
        ranked, cross_meta = cross_validate(non_empty, cfg)
        meta.update(cross_meta)
        meta["mode"] = "cross"
    else:
        merged: list[PointerChain] = []
        for group in file_chains:
            merged.extend(group)
        ranked = filter_and_rank(merged, cfg)
        meta["mode"] = "single"
        meta["unique_inputs"] = len(merged)
        if all_addresses and not ranked:
            warnings.append(
                "仅有生效地址、没有指针路径：请在 GG 中做指针搜索后再导入，或使用 online-search"
            )

    result = AnalyzeResult(
        chains=ranked,
        addresses=all_addresses,
        meta=meta,
        warnings=warnings,
    )

    if export_dir:
        export_all(
            result,
            export_dir,
            game=cfg.game_name,
            package=cfg.android_package or "com.example.game",
        )
    return result
