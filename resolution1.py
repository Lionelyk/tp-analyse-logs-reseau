def lire_logs(nom_fichier):
    logs = []
    with open(nom_fichier, "r") as f:
        for ligne in f:
            ligne = ligne.strip()
            if ligne:
                date, heure, ip, port, protocole, statut = ligne.split(";")
                logs.append({
                    "date": date,
                    "heure": heure,
                    "ip": ip,
                    "port": port,
                    "protocole": protocole,
                    "statut": statut
                })
    return logs


def calculer_statistiques(logs):
    total = len(logs)
    succes = 0
    echec = 0
    ports = {}
    ips = {}

    for log in logs:
        if log["statut"] == "SUCCES":
            succes += 1
        else:
            echec += 1

        ports[log["port"]] = ports.get(log["port"], 0) + 1
        ips[log["ip"]] = ips.get(log["ip"], 0) + 1

    port_plus_utilise = max(ports, key=ports.get)
    ip_plus_active = max(ips, key=ips.get)

    return total, succes, echec, ports, ips, port_plus_utilise, ip_plus_active


def detecter_suspects(logs):
    compteur = {}

    for log in logs:
        if log["statut"] == "ECHEC":
            cle = (log["ip"], log["port"])
            compteur[cle] = compteur.get(cle, 0) + 1

    suspects = []
    for (ip, port), nb in compteur.items():
        if nb > 5:
            suspects.append((ip, port, nb))

    return suspects


def generer_rapport(nom_fichier, stats, suspects):
    total, succes, echec, ports, ips, port_plus_utilise, ip_plus_active = stats

    with open(nom_fichier, "w") as f:
        f.write("=== RAPPORT D'ANALYSE RESEAU ===\n\n")
        f.write(f"Total connexions : {total}\n")
        f.write(f"Total succès : {succes}\n")
        f.write(f"Total échecs : {echec}\n")
        f.write(f"Port le plus utilisé : {port_plus_utilise}\n")
        f.write(f"IP la plus active : {ip_plus_active}\n\n")

        f.write("=== IP SUSPECTES ===\n")
        for ip, port, nb in suspects:
            f.write(f"{ip} sur port {port} ({nb} échecs)\n")

        f.write("\n=== TOP 3 PORTS ===\n")
        top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:3]
        for port, nb in top_ports:
            f.write(f"Port {port} : {nb} connexions\n")


def main():
    logs = lire_logs("network_log.txt")
    stats = calculer_statistiques(logs)
    suspects = detecter_suspects(logs)

    print("=== RESULTATS ===")
    print("Total connexions :", stats[0])
    print("Total succès :", stats[1])
    print("Total échecs :", stats[2])
    print("Port le plus utilisé :", stats[5])
    print("IP la plus active :", stats[6])
    print("\nIP suspectes :", suspects)

    generer_rapport("rapport_analyse.txt", stats, suspects)
    print("\nRapport généré : rapport_analyse.txt")


if __name__ == "__main__":
    main()

