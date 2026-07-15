"""Frida 向上搜指针（可选依赖）。"""

from __future__ import annotations

from gg_base_analyzer.models import AnalyzeConfig, PointerChain

_SEARCH_JS = r"""
'use strict';

function toPattern(addrPtr, pointerSize) {
  let n = BigInt(addrPtr.toString());
  if (pointerSize === 4) {
    n = n & 0xffffffffn;
  }
  const parts = [];
  for (let i = 0; i < pointerSize; i++) {
    const b = Number(n & 0xffn);
    parts.push(('0' + b.toString(16)).slice(-2));
    n = n >> 8n;
  }
  return parts.join(' ');
}

rpc.exports = {
  search(targetStr, pointerSize, maxResults, maxOffset, preferModules) {
    const target = ptr(targetStr);
    const results = [];
    const seen = {};
    const prefer = preferModules || [];
    const modules = Process.enumerateModules();

    function addHit(moduleName, moduleOffset, lastOff) {
      const key = moduleName + '|' + moduleOffset + '|' + lastOff;
      if (seen[key]) return;
      seen[key] = true;
      results.push({
        module: moduleName,
        module_offset: String(moduleOffset),
        offsets: [String(lastOff)],
      });
    }

    function scanNeedle(needle, lastOff, preferOnly) {
      const pattern = toPattern(needle, pointerSize);
      for (const m of modules) {
        if (results.length >= maxResults) return;
        const preferred = prefer.indexOf(m.name) >= 0;
        if (preferOnly && !preferred) continue;
        if (!preferred && !/\.so$/i.test(m.name)) continue;
        let ranges;
        try {
          ranges = m.enumerateRanges('r--');
        } catch (e) {
          continue;
        }
        for (const range of ranges) {
          if (results.length >= maxResults) return;
          const size = Math.min(range.size, 24 * 1024 * 1024);
          try {
            const hits = Memory.scanSync(range.base, size, pattern);
            for (const hit of hits) {
              const off = hit.address.sub(m.base).toInt32();
              if (off < 0) continue;
              addHit(m.name, off, lastOff);
              if (results.length >= maxResults) return;
            }
          } catch (e) {}
        }
      }
    }

    const deltas = [0, 4, 8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x40, 0x48, 0x50, 0x80, 0xA0, 0x100, 0x200];
    // 先扫优先模块的精确/近邻指针
    for (const d of deltas) {
      if (d > maxOffset) continue;
      scanNeedle(target.sub(d), d, true);
      if (results.length >= maxResults) break;
    }
    // 不够再扩到其它 .so
    if (results.length < Math.min(20, maxResults)) {
      for (const d of deltas) {
        if (d > maxOffset) continue;
        scanNeedle(target.sub(d), d, false);
        if (results.length >= maxResults) break;
      }
    }
    return results;
  }
};
"""


def frida_available() -> bool:
    try:
        import frida  # noqa: F401

        return True
    except ImportError:
        return False


def online_search_chains(
    package: str,
    address: int,
    cfg: AnalyzeConfig | None = None,
    *,
    device_id: str | None = None,
    spawn: bool = False,
    max_results: int = 80,
) -> list[PointerChain]:
    """Attach 游戏进程，搜索指向 address（或邻近）的一级指针候选。"""
    cfg = (cfg or AnalyzeConfig()).validate()
    if not frida_available():
        raise RuntimeError('未安装 frida。请执行: pip install -e ".[online]"')

    import frida

    mgr = frida.get_device_manager()
    device = mgr.get_device(device_id) if device_id else mgr.get_usb_device(timeout=5)

    session = None
    try:
        if spawn:
            pid = device.spawn([package])
            session = device.attach(pid)
            device.resume(pid)
        else:
            session = device.attach(package)

        script = session.create_script(_SEARCH_JS)
        script.load()
        raw = script.exports_sync.search(
            hex(address),
            cfg.pointer_size,
            max_results,
            cfg.max_single_offset,
            list(cfg.preferred_modules),
        )
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass

    chains: list[PointerChain] = []
    seen: set[tuple] = set()
    for item in raw or []:
        try:
            module = str(item.get("module") or "[anon]")
            module_offset = int(str(item.get("module_offset")), 0)
            offsets = tuple(int(str(x), 0) for x in (item.get("offsets") or [0]))
            c = PointerChain(
                module_name=module,
                module_offset=module_offset,
                offsets=offsets,
                source="online-frida",
            )
            key = c.dedupe_key()
            if key in seen:
                continue
            seen.add(key)
            chains.append(c)
        except (TypeError, ValueError):
            continue
    return chains
