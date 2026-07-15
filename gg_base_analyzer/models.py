from __future__ import annotations

from dataclasses import dataclass, field, fields


@dataclass
class PointerChain:
    module_name: str
    module_offset: int
    offsets: tuple[int, ...]
    score: float = 0.0
    source: str = ""
    field_name: str = ""
    value_type: str = "int32"
    verified: bool = False

    @property
    def depth(self) -> int:
        return len(self.offsets)

    def export_name(self, fallback_index: int) -> str:
        return self.field_name.strip() or f"chain_{fallback_index}"

    def dedupe_key(self) -> tuple:
        return (self.module_name.lower(), self.module_offset, self.offsets)

    def display(self) -> str:
        mod = self.module_name or "[anon]"
        offs = " → ".join(f"+0x{o:X}" for o in self.offsets) or "(direct)"
        return f"{mod}+0x{self.module_offset:X} {offs}"


@dataclass
class AddressHit:
    address: int
    value_type: str = "int32"
    note: str = ""
    value: str = ""


@dataclass
class AnalyzeConfig:
    max_depth: int = 6
    max_single_offset: int = 0x1000
    top_n: int = 30
    min_score: float = 0.0
    cross_min: int = 2
    require_all: bool = False
    fuzzy: bool = True
    fuzzy_last_offset_step: int = 0x8
    game_name: str = "game"
    android_package: str = ""
    pointer_size: int = 4
    preferred_modules: tuple[str, ...] = (
        "libil2cpp.so",
        "libunity.so",
        "libmain.so",
        "libcocos2d.so",
    )

    def validate(self) -> AnalyzeConfig:
        if self.top_n < 1:
            raise ValueError("top_n 必须 >= 1")
        if self.pointer_size not in (4, 8):
            raise ValueError("pointer_size 必须为 4 或 8")
        if self.cross_min < 1:
            raise ValueError("cross_min 必须 >= 1")
        return self


@dataclass
class AnalyzeResult:
    chains: list[PointerChain] = field(default_factory=list)
    addresses: list[AddressHit] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def config_from_dict(data: dict) -> AnalyzeConfig:
    names = {f.name for f in fields(AnalyzeConfig)}
    kwargs = {k: v for k, v in data.items() if k in names}
    if "preferred_modules" in kwargs and isinstance(kwargs["preferred_modules"], list):
        kwargs["preferred_modules"] = tuple(kwargs["preferred_modules"])
    return AnalyzeConfig(**kwargs).validate()
