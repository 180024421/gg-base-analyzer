from gg_base_analyzer.export.frida_script import result_to_frida
from gg_base_analyzer.export.lua_script import result_to_lua
from gg_base_analyzer.models import AnalyzeResult, PointerChain


def test_export_contains_read():
    result = AnalyzeResult(
        chains=[
            PointerChain(
                module_name="libil2cpp.so",
                module_offset=0x1000,
                offsets=(0x10, 0x20),
                field_name="gold",
            )
        ]
    )
    js = result_to_frida(result, package="com.demo")
    assert "readChain" in js
    assert "gold" in js
    lua = result_to_lua(result, game="demo")
    assert "read_chain" in lua
    assert "gold" in lua
