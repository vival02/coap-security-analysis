"""
analisi_sicurezza.py
====================
Analisi statistica del dataset prodotto da scanner_shodan.py.

Calcola e stampa:
  - Dimensioni del campione (IP unici)
  - Postura di sicurezza globale (vulnerabili vs protetti)
  - Distribuzione degli endpoint per categoria
  - Densità della superficie d'attacco per host vulnerabile

Input  : risultati_massivi_shodan.csv
Autore : Camilla Vivaldi (VR518695)
Corso  : Network Security – Università degli Studi di Verona
Data   : 10 Maggio 2026
"""

import csv
from collections import Counter, defaultdict

FILE_INPUT = "risultati_massivi_shodan.csv"

ip_unici = set()
stato_vulnerabilita_ip = {}
conteggio_categorie = Counter()
endpoint_per_ip = defaultdict(int)

print("[*] Avvio analisi del dataset...\n")

try:
    with open(FILE_INPUT, mode="r", encoding="utf-8-sig") as f:
        campione = f.read(1024)
        f.seek(0)
        separatore = ";" if ";" in campione else ","
        print(f"[*] Separatore rilevato: '{separatore}'")

        reader = csv.DictReader(f, delimiter=separatore)

        for row in reader:
            ip          = row.get("IP Target", "").strip()
            vuln_radice = row.get("Vulnerabilità Radice (Info Leak)", "").strip()
            percorso    = row.get("Percorso", "").strip()
            categoria   = row.get("Categoria", "").strip()

            if not ip:
                continue

            ip_unici.add(ip)

            # Postura: se almeno una riga dell'IP è SI, l'host è vulnerabile
            if ip not in stato_vulnerabilita_ip:
                stato_vulnerabilita_ip[ip] = vuln_radice
            elif "SI" in vuln_radice.upper():
                stato_vulnerabilita_ip[ip] = vuln_radice

            # Categorie ed endpoint (solo host vulnerabili, esclusa radice)
            if categoria and "SI" in vuln_radice.upper():
                conteggio_categorie[categoria] += 1
                if percorso != "/":
                    endpoint_per_ip[ip] += 1

except FileNotFoundError:
    print(f"[ERRORE] File '{FILE_INPUT}' non trovato.")
    exit()

# ── Statistiche ───────────────────────────────────────────────────────────────

totale_ip      = len(ip_unici)
ip_vulnerabili = sum(1 for s in stato_vulnerabilita_ip.values() if "SI" in s.upper())
ip_protetti    = totale_ip - ip_vulnerabili

print("\n" + "="*55)
print("  RISULTATI ANALISI STATISTICA")
print("="*55)

print(f"\n[1] Dimensioni del campione")
print(f"    IP unici scansionati : {totale_ip}")

print(f"\n[2] Postura di sicurezza globale")
if totale_ip > 0:
    print(f"    Vulnerabili (Info Leak) : {ip_vulnerabili} ({ip_vulnerabili/totale_ip*100:.1f}%)")
    print(f"    Protetti / Irragg.      : {ip_protetti}  ({ip_protetti/totale_ip*100:.1f}%)")

print(f"\n[3] Distribuzione endpoint per categoria")
for cat, count in conteggio_categorie.most_common():
    print(f"    {cat:<25} : {count} endpoint")

print(f"\n[4] Densità superficie d'attacco")
if endpoint_per_ip:
    media = sum(endpoint_per_ip.values()) / len(endpoint_per_ip)
    massimo = max(endpoint_per_ip.values())
    print(f"    Media endpoint per host vulnerabile : {media:.1f}")
    print(f"    Massimo endpoint su un singolo host : {massimo}")

print("="*55)
