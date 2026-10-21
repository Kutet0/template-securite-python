from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import rdpcap, sniff
from scapy.layers.http import HTTP

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
        for packet in self.packets:
            noms = []
            for layer in packet.layers():
                if layer.__name__ != "Raw" and layer.__name__ != "Padding":
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
