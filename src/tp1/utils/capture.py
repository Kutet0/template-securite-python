from urllib.parse import unquote

from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import ARP

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import sniff, rdpcap
from scapy.layers.http import HTTP, HTTPRequest


class Capture:
    def __init__(self, pcap: str | None = None, iface: str | None = None) -> None:
        self.pcap = pcap
        self.iface = iface
        self.summary = ""
        self.packets = []

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        if self.pcap is not None:
            logger.info(f"Capture traffic from {self.pcap}")
            self.packets = rdpcap(self.pcap)
        elif self.iface is not None:
            logger.info(f"Capture traffic from {self.iface}")
            self.packets = sniff(iface=self.iface, timeout=20)
        else:
            interface = choose_interface()
            logger.info(f"Capture traffic from interface {interface}")
            self.packets = sniff(iface=interface, timeout=20)
        logger.info(f"{len(self.packets)} packets captured")

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        return ""

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        compteur = {}
        A_IGNORER = {"Raw", "Padding", "HTTPRequest", "HTTPResponse"}
        for packet in self.packets:
            noms = []
            for layer in packet.layers():
                if layer.__name__ not in A_IGNORER:
                    noms.append(layer.__name__)

            for nom in noms:
                if nom.startswith("ICMPv6"):
                    nom = "ICMPv6"
                if nom == "Ether":
                    nom = "Ethernet"

                if nom in compteur:
                    compteur[nom] += 1
                else:
                    compteur[nom] = 1
        return compteur

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.detect_arp_spoofing()
        self.detect_port_scan()
        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary

    def detect_arp_spoofing(self) -> list:
        ip_macs = {}
        mac_count = {}
        for packet in self.packets:
            if packet.haslayer(ARP) and packet[ARP].op == 2:
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc

                if ip not in ip_macs:
                    ip_macs[ip] = set()
                ip_macs[ip].add(mac)

                if mac not in mac_count:
                    mac_count[mac] = 1
                else:
                    mac_count[mac] += 1
        logger.debug(f"{ip_macs} / {mac_count}")

        attacks = []
        for ip, mac in ip_macs.items():
            if len(mac) > 1:
                attacker = None
                best = -1
                for m in mac:
                    if mac_count[m] > best:
                        best = mac_count[m]
                        attacker = m
                if attacker is not None:
                    attacks.append({"type": "arp_spoofing", "attacker": attacker})
                    logger.info(f"{ip} -> {attacker}")
        return attacks

    def detect_port_scan(self) -> list:
        ports_par_ip = {}
        for packet in self.packets:
            if packet.haslayer(TCP) and packet[TCP].flags == "S":
                ip = packet[IP].src
                port = packet[TCP].dport
                if ip not in ports_par_ip:
                    ports_par_ip[ip] = set()
                ports_par_ip[ip].add(port)
        SEUIL = 20
        attacks = []
        for ip, ports in ports_par_ip.items():
            if len(ports) > SEUIL:
                attacks.append({"type": "port_scan", "attacker": ip})
        return attacks

    def detect_sql_injection(self) -> list:
        attacks = []
        motifs = ["' or 1=1", "union select", "' or '1'='1", "or 1=1"]
        for packet in self.packets:
            if packet.haslayer(HTTPRequest):
                path = packet[HTTPRequest].Path.decode(errors="replace")
                path = unquote(path)
                path = path.lower()
                for motif in motifs:
                    if motif in path:
                        attacks.append({"type": "sql_injection", "attacker": packet[IP].src})
                        break
        return attacks

    def find_flag(self) -> str:
        for packet in self.packets:
            if packet.haslayer(HTTPRequest):
                path = packet[HTTPRequest].Path.decode(errors="replace")
                debut = path.find("ESGI{")
                if debut != -1:
                    fin = path.find("}", debut)
                    return path[debut:fin+1]
        return ""