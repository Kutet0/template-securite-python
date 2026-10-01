'''noms = ["TCP", "TCP", "DNS", "TCP", "ICMP"]
compteur = {}

for nom in noms:
    if nom in compteur:
        compteur[nom] += 1
    else:
        compteur[nom] = 1

print(compteur)'''

protocole = "ICMPv6ND_NA"
protocole2 = "ICMPv6"

print(protocole.startswith(protocole2))
