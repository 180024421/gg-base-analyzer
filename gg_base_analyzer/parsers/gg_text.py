"""GameGuardian 文本导出宽松解析。"""

from __future__ import annotations

import re
from pathlib import Path

from gg_base_analyzer.models import AddressHit, PointerChain

_HEX = re.compile(r"0x([0-9A-Fa-f]+)")
_ADDR_LINE = re.compile(
    r"(?:^|\s)(?:0x)?([0-9A-Fa-f]{6,16})(?:\s|$|,|;|:)",
    re.IGNORECASE,
)
_SO = re.compile(r"([\w.\-]+\.so)", re.IGNORECASE)
_OFFSET = re.compile(r"(?:\+|→|->|,|\s)(?:0x)?([0-9A-Fa-f]+)", re.IGNORECASE)
_MODULE_PLUS = re.compile(
    r"([\w.\-]+\.so)\s*\+\s*(?:0x)?([0-9A-Fa-f]+)",
    re.IGNORECASE,
)
_PATH_SPLIT = re.compile(r"\s*(?:→|->|;)\s*")


def _parse_int(token: str) -> int | None:
    token = token.strip().rstrip(",")
    if not token:
        return None
    try:
        if token.lower().startswith("0x"):
            return int(token, 16)
        if re.fullmatch(r"[0-9A-Fa-f]+", token) and any(c.isalpha() for c in token):
            return int(token, 16)
        return int(token, 0)
    except ValueError:
        return None


def parse_gg_text(text: str, *, source: str = "") -> tuple[list[PointerChain], list[AddressHit], list[str]]:
    chains: list[PointerChain] = []
    addresses: list[AddressHit] = []
    warnings: list[str] = []
    seen_addr: set[int] = set()
    seen_chain: set[tuple] = set()

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        chain = _try_parse_chain_line(line, source=source or f"line:{lineno}")
        if chain is not None:
            key = chain.dedupe_key()
            if key not in seen_chain:
                seen_chain.add(key)
                chains.append(chain)
            continue

        # 纯地址行
        if _looks_like_path(line):
            warnings.append(f"第 {lineno} 行疑似路径但未能解析: {line[:80]}")
            continue

        m = _ADDR_LINE.search(line)
        if m:
            addr = int(m.group(1), 16)
            if addr not in seen_addr:
                seen_addr.add(addr)
                note = ""
                if " " in line:
                    parts = line.split(None, 1)
                    if len(parts) > 1 and not parts[1].lower().startswith("0x"):
                        note = parts[1][:80]
                addresses.append(AddressHit(address=addr, note=note))
            continue

        if any(ch.isalnum() for ch in line):
            warnings.append(f"第 {lineno} 行已跳过: {line[:80]}")

    return chains, addresses, warnings


def _looks_like_path(line: str) -> bool:
    return bool(_SO.search(line)) or "→" in line or "->" in line or "+" in line


def _try_parse_chain_line(line: str, *, source: str) -> PointerChain | None:
    mod_m = _MODULE_PLUS.search(line)
    if mod_m:
        module = mod_m.group(1)
        module_offset = int(mod_m.group(2), 16)
        rest = line[mod_m.end() :]
        offsets = _extract_offsets(rest)
        return PointerChain(
            module_name=module,
            module_offset=module_offset,
            offsets=tuple(offsets),
            source=source,
        )

    # [anon]+0x... 或 纯 hex 基址 + offsets
    anon = re.search(r"\[anon\]\s*\+\s*(?:0x)?([0-9A-Fa-f]+)", line, re.I)
    if anon:
        base = int(anon.group(1), 16)
        offsets = _extract_offsets(line[anon.end() :])
        return PointerChain(
            module_name="[anon]",
            module_offset=base,
            offsets=tuple(offsets),
            source=source,
        )

    # 形如: 0xABCDEF → 0x10 → 0x20  （绝对路径，记为 anon 基）
    if ("→" in line or "->" in line) and _HEX.search(line):
        parts = _PATH_SPLIT.split(line)
        nums: list[int] = []
        for p in parts:
            hm = _HEX.search(p) or re.search(r"^([0-9A-Fa-f]+)$", p.strip())
            if not hm:
                continue
            g = hm.group(1) if hm.lastindex else hm.group(0)
            nums.append(int(g, 16))
        if len(nums) >= 2:
            return PointerChain(
                module_name="[anon]",
                module_offset=nums[0],
                offsets=tuple(nums[1:]),
                source=source,
            )
    return None


def _extract_offsets(fragment: str) -> list[int]:
    offsets: list[int] = []
    for m in _OFFSET.finditer(fragment):
        offsets.append(int(m.group(1), 16))
    return offsets


def load_gg_file(path: str | Path) -> tuple[list[PointerChain], list[AddressHit], list[str]]:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    return parse_gg_text(text, source=str(p))
