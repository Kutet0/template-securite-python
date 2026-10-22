# TP1 — IDS/IPS maison

Outil d'analyse réseau en Python avec Scapy il lit une capture réseau (PCAP ou interface live), compte les paquets par protocole, détecte des attaques et produit un report.json.

## Installation

```bash
poetry install
```

## Utilisation

```bash
poetry run tp1 --pcap capture.pcap --out report.json
```

Options :
- `--pcap` : fichier PCAP à analyser
- `--iface` : interface réseau à sniffer
- `--out` : chemin du report.json (défaut : report.json)

## Détections

- Comptage des protocoles (Ethernet, IP, TCP, UDP, ICMP, DNS, ARP, HTTP)
- ARP spoofing (une IP annoncée par plusieurs MAC)
- Scan de ports (nombreux SYN vers des ports différents)
- Injection SQL (motifs suspects dans les requêtes HTTP)
- Extraction du flag

## Structure

Le code vit dans `src/tp1/`, point d'entrée `src/tp1/main.py`.