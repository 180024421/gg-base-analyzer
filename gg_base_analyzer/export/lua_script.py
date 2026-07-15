from __future__ import annotations

from pathlib import Path

from gg_base_analyzer.models import AnalyzeResult


def result_to_lua(result: AnalyzeResult, *, game: str = "game") -> str:
    lines = [
        "-- gg-base-analyzer Lua read-chain helper (Auto Script Studio friendly)",
        f"-- game: {game}",
        "",
        "local M = {}",
        "",
        "function M.read_chain(bot, module_name, module_offset, offsets, value_type)",
        "  local base = bot:module_base(module_name)",
        "  if not base then error('module not found: ' .. tostring(module_name)) end",
        "  local addr = base + module_offset",
        "  for i = 1, #offsets - 1 do",
        "    addr = bot:read_pointer(addr + offsets[i])",
        "    if not addr or addr == 0 then error('null pointer at ' .. i) end",
        "  end",
        "  if #offsets > 0 then addr = addr + offsets[#offsets] end",
        "  value_type = value_type or 'int32'",
        "  if value_type == 'float' then return bot:read_float(addr) end",
        "  if value_type == 'int64' then return bot:read_i64(addr) end",
        "  return bot:read_i32(addr)",
        "end",
        "",
        "function M.read_all(bot)",
        "  local out = {}",
    ]
    for i, c in enumerate(result.chains, 1):
        name = c.export_name(i)
        offs = ", ".join(f"0x{o:X}" for o in c.offsets)
        mod = c.module_name if c.module_name not in ("", "[anon]") else "libil2cpp.so"
        lines.append(f"  -- {c.display()}")
        lines.append(
            f"  out.{name} = M.read_chain(bot, '{mod}', 0x{c.module_offset:X}, "
            f"{{{offs}}}, '{c.value_type or 'int32'}')"
        )
    lines.extend(
        [
            "  return out",
            "end",
            "",
            "return M",
            "",
        ]
    )
    return "\n".join(lines)


def save_lua_script(result: AnalyzeResult, output: str | Path, *, game: str = "game") -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result_to_lua(result, game=game), encoding="utf-8")
    return path
