from pathlib import Path

from gg_base_analyzer.parsers import load_gg_file, load_gg_json, parse_gg_text

FIX = Path(__file__).parent / "fixtures"


def test_parse_paths_file():
    chains, addrs, warns = load_gg_file(FIX / "gg_paths_r1.txt")
    assert len(chains) >= 3
    assert any(c.module_name == "libil2cpp.so" for c in chains)
    assert addrs == []


def test_parse_addresses():
    chains, addrs, warns = load_gg_file(FIX / "gg_addresses.txt")
    assert chains == []
    assert any(a.address == 0x7E33D6FC for a in addrs)


def test_parse_json():
    chains, addrs, warns = load_gg_json(FIX / "sample_chains.json")
    assert len(chains) == 1
    assert chains[0].field_name == "gold"
    assert addrs[0].address == 0x7E33D6FC


def test_parse_bad_line_skipped():
    chains, addrs, warns = parse_gg_text("not a valid line\nlibil2cpp.so+0x10 → 0x4\n")
    assert len(chains) == 1
    assert warns
