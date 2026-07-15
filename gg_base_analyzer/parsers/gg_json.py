"""工具自有 JSON 格式。"""

from __future__ import annotations

import json
from pathlib import Path

from gg_base_analyzer.models import AddressHit, PointerChain


def _as_int(v) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 0)
    raise TypeError(f"无法解析整数: {v!r}")


def load_gg_json(path: str | Path) -> tuple[list[PointerChain], list[AddressHit], list[str]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    warnings: list[str] = []
    chains: list[PointerChain] = []
    addresses: list[AddressHit] = []

    for item in data.get("paths") or data.get("chains") or []:
        try:
            chains.append(
                PointerChain(
                    module_name=str(item.get("module") or item.get("module_name") or "[anon]"),
                    module_offset=_as_int(item.get("module_offset", 0)),
                    offsets=tuple(_as_int(x) for x in item.get("offsets") or []),
                    field_name=str(item.get("field_name") or ""),
                    value_type=str(item.get("value_type") or "int32"),
                    source=str(path),
                    score=float(item.get("score") or 0),
                    verified=bool(item.get("verified")),
                )
            )
        except (TypeError, ValueError) as e:
            warnings.append(f"跳过无效 path: {e}")

    for item in data.get("addresses") or []:
        try:
            addresses.append(
                AddressHit(
                    address=_as_int(item.get("address")),
                    value_type=str(item.get("value_type") or "int32"),
                    note=str(item.get("note") or ""),
                    value=str(item.get("value") or ""),
                )
            )
        except (TypeError, ValueError) as e:
            warnings.append(f"跳过无效 address: {e}")

    return chains, addresses, warnings
