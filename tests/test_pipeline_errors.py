from unittest.mock import patch

from app.pipeline.pyshark_pass import parse_pcap_pyshark


def test_parse_pcap_missing_file():
    result = parse_pcap_pyshark("non_existent.pcap", None, None, None)
    assert result["flows"] == []
    assert len(result["artifacts"]["ips"]) == 0

def test_parse_pcap_invalid_limit():
    # Should handle invalid limit gracefully (log error and continue with None)
    # We need to mock os.path.exists to pass the first check
    with patch("os.path.exists", return_value=True):
        # And mock find_bin to avoid actual tshark call or failure
        with patch("app.pipeline.pyshark_pass.find_bin", return_value=None):
             result = parse_pcap_pyshark("test.pcap", "invalid", None, None)
             # It should return empty result because tshark is not found (mocked None)
             # But importantly, it shouldn't crash on "invalid" limit
             assert result["flows"] == []

def test_parse_pcap_tshark_missing():
    with patch("os.path.exists", return_value=True):
        with patch("app.pipeline.pyshark_pass.find_bin", return_value=None):
            result = parse_pcap_pyshark("test.pcap", 100, None, None)
            assert result["flows"] == []
