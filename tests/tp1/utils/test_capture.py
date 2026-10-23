from unittest.mock import patch
from src.tp1.utils.capture import Capture
from src.tp1.utils.report import Report
from scapy.all import Ether, IP, TCP, ARP
from scapy.layers.http import HTTPRequest
import json


def test_capture_init():
    # When
    capture = Capture()

    # Then
    assert capture.pcap is None
    assert capture.iface is None
    assert capture.summary == ""
    assert capture.packets == []


def test_sort_network_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == ""  # Method currently returns None


def test_get_all_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == {}  # Method currently returns None


def test_analyse():
    # Given
    capture = Capture()

    # When
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    # Then
    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"


def test_get_summary():
    # Given
    capture = Capture()
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


def test_gen_summary():
    # Given
    capture = Capture()

    # When
    result = capture._gen_summary()

    # Then
    assert result == ""  # Method currently returns empty string


def test_get_all_protocols_compte_les_couches():
    # Given
    capture = Capture()
    capture.packets = [Ether() / IP() / TCP(), Ether() / IP() / TCP(), Ether() / ARP()]
    # when
    result = capture.get_all_protocols()
    # then
    assert result["TCP"] == 2
    assert result["IP"] == 2
    assert result["ARP"] == 1
    assert result["Ethernet"] == 3


def test_detect_arp_spoofing():
    # Given
    capture = Capture()
    capture.packets = [
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:aa"),  # attaquant
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:aa"),  # attaquant (flood)
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="bb:bb:bb:bb:bb:bb"),  # vraie passerelle
    ]
    # When
    result = capture.detect_arp_spoofing()
    # Then
    assert result == [{"type": "arp_spoofing", "attacker": "aa:aa:aa:aa:aa:aa"}]


def test_detect_port_scan():
    # Given
    capture = Capture()
    capture.packets = [IP(src="10.0.0.5") / TCP(dport=p, flags="S") for p in range(30)]
    # When
    result = capture.detect_port_scan()
    # Then
    assert result == [{"type": "port_scan", "attacker": "10.0.0.5"}]


def test_detect_sql_injection():
    # Given
    capture = Capture()
    capture.packets = [IP(src="10.0.0.9") / TCP() / HTTPRequest(Path=b"/login?user=admin' or 1=1--")]
    # When
    result = capture.detect_sql_injection()
    # Then
    assert result == [{"type": "sql_injection", "attacker": "10.0.0.9"}]


def test_find_flag():
    # Given
    capture = Capture()
    capture.packets = [IP() / TCP() / HTTPRequest(Path=b"/page?token=ESGI{test123}")]
    # When
    result = capture.find_flag()
    # Then
    assert result == "ESGI{test123}"


def test_save_json(tmp_path):
    # Given
    capture = Capture()
    capture.packets = [Ether() / IP() / TCP()]
    report = Report(capture, "report.pdf", "")
    chemin = tmp_path / "report.json"
    # When
    report.save_json(str(chemin))
    # Then
    data = json.loads(chemin.read_text())
    assert "protocols" in data
    assert "attacks" in data
    assert "flag" in data


def test_concat_report():
    # Given
    capture = Capture()
    report = Report(capture, "report.pdf", "mon résumé")
    report.title = "Titre"
    report.array = "tableau"
    report.graph = "graphe"
    # When
    result = report.concat_report()
    # Then
    assert result == "Titremon résumétableaugraphe"
