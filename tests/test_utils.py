from app.utils.common import is_public_ipv4, make_slug, uniq_sorted


def test_is_public_ipv4():
    assert is_public_ipv4("8.8.8.8") is True
    assert is_public_ipv4("192.168.1.1") is False
    assert is_public_ipv4("10.0.0.1") is False
    assert is_public_ipv4("127.0.0.1") is False
    assert is_public_ipv4("invalid") is False
    assert is_public_ipv4(None) is False

def test_make_slug():
    assert make_slug("Hello World") == "hello_world"
    assert make_slug("  Test  ") == "__test__"
    assert make_slug("Foo_Bar") == "foo_bar"

def test_uniq_sorted():
    assert uniq_sorted([3, 1, 2, 1]) == [1, 2, 3]
    assert uniq_sorted([]) == []
    assert uniq_sorted(None) == []
