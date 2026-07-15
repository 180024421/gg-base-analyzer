from __future__ import annotations

from gg_base_analyzer.models import AnalyzeConfig, PointerChain

PREFERRED_BONUS = 40.0
DEPTH_PENALTY = 6.0
OFFSET_PENALTY = 0.002
ANON_PENALTY = 25.0


def score_chain(chain: PointerChain, cfg: AnalyzeConfig) -> float:
    score = 100.0
    mod = (chain.module_name or "").lower()
    preferred = {m.lower() for m in cfg.preferred_modules}
    if mod in preferred:
        score += PREFERRED_BONUS
    elif mod in ("", "[anon]", "anonymous"):
        score -= ANON_PENALTY
    score -= chain.depth * DEPTH_PENALTY
    for off in chain.offsets:
        if off > cfg.max_single_offset:
            score -= 20
        score -= off * OFFSET_PENALTY
    if chain.module_offset < 0:
        score -= 50
    return score


def filter_and_rank(
    chains: list[PointerChain],
    cfg: AnalyzeConfig,
) -> list[PointerChain]:
    ranked: list[PointerChain] = []
    seen: set[tuple] = set()
    for c in chains:
        if c.depth > cfg.max_depth:
            continue
        if any(o > cfg.max_single_offset * 4 for o in c.offsets):
            continue
        key = c.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        scored = PointerChain(
            module_name=c.module_name,
            module_offset=c.module_offset,
            offsets=c.offsets,
            score=score_chain(c, cfg),
            source=c.source,
            field_name=c.field_name,
            value_type=c.value_type,
            verified=c.verified,
        )
        if scored.score >= cfg.min_score:
            ranked.append(scored)
    ranked.sort(key=lambda x: (-x.score, x.depth, x.module_name.lower()))
    return ranked[: cfg.top_n]
