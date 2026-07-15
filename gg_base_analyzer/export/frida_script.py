from __future__ import annotations

from pathlib import Path

from gg_base_analyzer.models import AnalyzeResult


def result_to_frida(result: AnalyzeResult, *, package: str = "com.example.game") -> str:
    lines = [
        "// gg-base-analyzer Frida guest script",
        f"// frida -U -f {package} -l this_file.js --no-pause",
        "",
        "function readChain(moduleName, moduleOffset, offsets, type) {",
        "  const m = Process.findModuleByName(moduleName);",
        "  if (!m) throw new Error('module not found: ' + moduleName);",
        "  let addr = m.base.add(ptr(moduleOffset));",
        "  for (let i = 0; i < offsets.length - 1; i++) {",
        "    addr = addr.add(offsets[i]).readPointer();",
        "    if (addr.isNull()) throw new Error('null pointer at ' + i);",
        "  }",
        "  if (offsets.length) addr = addr.add(offsets[offsets.length - 1]);",
        "  if (type === 'float') return addr.readFloat();",
        "  if (type === 'int64') return addr.readS64();",
        "  return addr.readS32();",
        "}",
        "",
        "setImmediate(function () {",
    ]
    for i, c in enumerate(result.chains, 1):
        name = c.export_name(i)
        offs = ", ".join(f"0x{o:X}" for o in c.offsets)
        mod = c.module_name if c.module_name not in ("", "[anon]") else "libil2cpp.so"
        lines.append(f"  // {c.display()}")
        lines.append("  try {")
        lines.append(
            f"    const {name} = readChain('{mod}', 0x{c.module_offset:X}, "
            f"[{offs}], '{c.value_type or 'int32'}');"
        )
        lines.append(f"    console.log('{name}=', {name});")
        lines.append("  } catch (e) { console.log('fail " + name + "', e); }")
        lines.append("")
    lines.append("});")
    lines.append("")
    return "\n".join(lines)


def save_frida_script(
    result: AnalyzeResult,
    output: str | Path,
    *,
    package: str = "com.example.game",
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result_to_frida(result, package=package), encoding="utf-8")
    return path
