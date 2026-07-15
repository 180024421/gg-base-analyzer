from pathlib import Path

from gg_base_analyzer.models import AnalyzeConfig
from gg_base_analyzer.pipeline import analyze_files

FIX = Path(__file__).parent / "fixtures"


def test_cross_analyze(tmp_path):
    cfg = AnalyzeConfig(game_name="demo", cross_min=2, top_n=20)
    result = analyze_files(
        [FIX / "gg_paths_r1.txt", FIX / "gg_paths_r2.txt"],
        cfg,
        export_dir=tmp_path,
    )
    assert result.meta["mode"] == "cross"
    assert result.meta["in_all"] >= 1
    assert any(c.module_name == "libil2cpp.so" for c in result.chains)
    assert (tmp_path / "demo_chains.json").exists()
    assert (tmp_path / "demo_frida.js").exists()
    assert (tmp_path / "demo_read.lua").exists()


def test_single_addresses_warns():
    result = analyze_files([FIX / "gg_addresses.txt"], AnalyzeConfig(cross_min=2))
    assert result.meta["mode"] == "single"
    assert result.addresses
    assert any("指针" in w for w in result.warnings)
