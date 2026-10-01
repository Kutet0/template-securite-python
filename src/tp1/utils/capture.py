from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import *

class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
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
            proto = noms[-1]

            if proto.startswith("ICMPv6"):
                proto = "ICMPv6"

            if proto in compteur:
                compteur[proto] += 1
            else:
                compteur[proto] = 1
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
