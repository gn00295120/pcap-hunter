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


def test_filter_flows_by_ips():
    from app.utils.common import filter_flows_by_ips

    flows = [
        {"src": "1.1.1.1", "dst": "2.2.2.2"},
        {"src": "3.3.3.3", "dst": "4.4.4.4"},
        {"src": "1.1.1.1", "dst": "5.5.5.5"},
    ]

    # Test empty selection (return all)
    assert len(filter_flows_by_ips(flows, set())) == 3

    # Test selection
    selected = {"1.1.1.1"}
    filtered = filter_flows_by_ips(flows, selected)
    assert len(filtered) == 2
    assert filtered[0]["dst"] == "2.2.2.2"
    assert filtered[1]["dst"] == "5.5.5.5"

    # Test no match
    assert len(filter_flows_by_ips(flows, {"9.9.9.9"})) == 0
    assert uniq_sorted([]) == []
    assert uniq_sorted(None) == []
