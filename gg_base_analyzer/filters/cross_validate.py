from __future__ import annotations

from collections import defaultdict

from gg_base_analyzer.filters.scorer import filter_and_rank, score_chain
from gg_base_analyzer.models import AnalyzeConfig, PointerChain


def _fuzzy_key(chain: PointerChain, step: int) -> tuple:
    if not chain.offsets:
        return chain.dedupe_key()
    *head, last = chain.offsets
    return (
        chain.module_name.lower(),
        chain.module_offset,
        tuple(head),
        (last // step) if step > 0 else last,
    )


def cross_validate(
    file_chains: list[list[PointerChain]],
    cfg: AnalyzeConfig,
) -> tuple[list[PointerChain], dict]:
    if len(file_chains) < cfg.cross_min:
        raise ValueError(f"交叉验证至少需要 {cfg.cross_min} 个文件的结果")

    total = len(file_chains)
    counter: dict[tuple, list[PointerChain]] = defaultdict(list)

    for chains in file_chains:
        local: dict[tuple, PointerChain] = {}
        for c in chains:
            key = _fuzzy_key(c, cfg.fuzzy_last_offset_step) if cfg.fuzzy else c.dedupe_key()
            if key not in local:
                local[key] = c
        for key, c in local.items():
            counter[key].append(c)

    min_hits = total if cfg.require_all else cfg.cross_min
    stable: list[PointerChain] = []
    in_all = 0
    for key, items in counter.items():
        hits = len(items)
        if hits >= total:
            in_all += 1
        if hits < min_hits:
            continue
        best = max(items, key=lambda c: score_chain(c, cfg))
        scored = PointerChain(
            module_name=best.module_name,
            module_offset=best.module_offset,
            offsets=best.offsets,
            score=score_chain(best, cfg) + hits * 15,
            source=f"cross:{hits}/{total}",
            field_name=best.field_name,
            value_type=best.value_type,
            verified=best.verified,
        )
        stable.append(scored)

    ranked = filter_and_rank(stable, cfg)
    meta = {
        "files": total,
        "unique_keys": len(counter),
        "stable_keys": len(stable),
        "in_all": in_all,
        "stability_ratio": round(in_all / max(len(counter), 1), 4),
        "require_all": cfg.require_all,
        "fuzzy": cfg.fuzzy,
    }
    return ranked, meta
