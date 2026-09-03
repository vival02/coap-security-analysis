"""
error401.py
===========
Fase 2 della pipeline di analisi CoAP.

Retest su tutti gli IP unici del dataset per registrare il codice
CoAP esatto, distinguendo le categorie aggregate nel NO della Fase 1.

Input  : risultati_massivi_shodan.csv
Output : classificazione_dettagliata_sicurezza.csv
Autore : Camilla Vivaldi
Corso  : Network Security – Università degli Studi di Verona
Data   : 10 Maggio 2026
"""

import csv
import pandas as pd
from coapthon.client.helperclient import HelperClient

FILE_INPUT  = "risultati_massivi_shodan.csv"
FILE_OUTPUT = "classificazione_dettagliata_sicurezza.csv"
TIMEOUT     = 3
PORTA       = 5683


def analizza_postura(ip):
    client = HelperClient(server=(ip, PORTA))
    try:
        res = client.get("/", timeout=TIMEOUT)

        if res is None:
            return "TIMEOUT (Drop di Rete / Firewall)"

        # coapthon3 espone il codice sia come stringa "2.05" sia come intero 69
        if "2." in str(res.code) or str(res.code) == "69":
            return "VULNERABILE (Info Leak - Assenza Access Control)"
        elif "4.01" in str(res.code) or str(res.code) == "129":
            return "SICURO (4.01 Unauthorized - Livello Applicativo)"
        else:
            return f"ALTRO (Codice CoAP: {res.code})"

    except Exception:
        return "TIMEOUT (Drop di Rete / Firewall)"
    finally:
        client.stop()


# Deduplica: ogni IP deve essere testato una sola volta
df = pd.read_csv(FILE_INPUT)
ip_unici = list(set(df.iloc[:, 0].dropna().tolist()))
print(f"[*] IP unici da ritestare: {len(ip_unici)}\n")

contatori = {"VULNERABILE": 0, "SICURO": 0, "ALTRO": 0, "TIMEOUT": 0}

with open(FILE_OUTPUT, mode="w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["IP Target", "Classificazione"])

    for i, ip in enumerate(ip_unici, 1):
        print(f"[{i:04d}/{len(ip_unici)}] {ip}", end=" ... ")
        risultato = analizza_postura(ip)
        writer.writerow([ip, risultato])
        print(risultato)

        if "VULNERABILE" in risultato:   contatori["VULNERABILE"] += 1
        elif "SICURO" in risultato:      contatori["SICURO"] += 1
        elif "TIMEOUT" in risultato:     contatori["TIMEOUT"] += 1
        else:                            contatori["ALTRO"] += 1

print(f"\n{'='*55}")
print("  RIEPILOGO")
print(f"{'='*55}")
for cat, count in contatori.items():
    print(f"  {cat:<15} : {count:>4} ({count/len(ip_unici)*100:.1f}%)")

if contatori["SICURO"] == 0:
    print("\n  [!!!] Nessun host implementa 4.01 Unauthorized.")
    print("        La protezione osservata e' interamente perimetrale.")

print(f"\n[+] Output: {FILE_OUTPUT}")