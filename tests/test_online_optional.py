from gg_base_analyzer.online.frida_search import frida_available


def test_frida_available_bool():
    assert isinstance(frida_available(), bool)
