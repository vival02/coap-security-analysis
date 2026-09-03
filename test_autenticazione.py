"""
test_autenticazione.py
======================
Verifica dell'Access Control sull'ecosistema And-Link.

Seleziona dal dataset gli host con endpoint classificati come
CRITICO/CONTROLLO e testa se richiedono autenticazione (4.01)
o sono liberamente accessibili (2.05 Content).

Input  : risultati_massivi_shodan.csv
Autore : Camilla Vivaldi
Corso  : Network Security – Università degli Studi di Verona
Data   : 10 Maggio 2026
"""

import pandas as pd
from coapthon.client.helperclient import HelperClient

FILE_INPUT   = "risultati_massivi_shodan.csv"
CAMPIONE     = 50
TIMEOUT      = 3
PORTA        = 5683


def testa_endpoint(ip, percorso):
    client = HelperClient(server=(ip, PORTA))
    try:
        res = client.get(percorso, timeout=TIMEOUT)
        if res is None:
            return "TIMEOUT", None

        codice = str(res.code)
        if "2." in codice or codice == "69":
            return "VULNERABILE", res.payload
        elif "4.01" in codice or codice == "129":
            return "SICURO (4.01)", None
        else:
            return f"ALTRO ({codice})", None

    except Exception:
        return "TIMEOUT", None
    finally:
        client.stop()


print("[*] Caricamento dataset...")
df = pd.read_csv(FILE_INPUT)

# Filtriamo solo gli endpoint critici dell'ecosistema And-Link
maschera = (
    df["Categoria"].str.contains("CRITICO", case=False, na=False) &
    df["Percorso"].str.contains("qlink|apdevice|gw", case=False, na=False)
)
target = df[maschera].drop_duplicates(subset=["IP Target"]).head(CAMPIONE)
print(f"[*] Target selezionati: {len(target)}\n")

risultati = {"VULNERABILE": 0, "SICURO (4.01)": 0, "TIMEOUT": 0, "ALTRO": 0}

for _, row in target.iterrows():
    ip       = row["IP Target"]
    percorso = row["Percorso"]

    print(f"-> {ip} | {percorso}", end=" ... ")
    esito, payload = testa_endpoint(ip, percorso)
    print(esito)

    # Mostra un estratto del payload se l'endpoint è aperto
    if payload:
        estratto = payload[:120] + "..." if len(payload) > 120 else payload
        print(f"   [DATA]: {estratto}")

    if esito in risultati:
        risultati[esito] += 1
    else:
        risultati["ALTRO"] += 1

n = len(target)
print(f"\n{'='*55}")
print("  RIEPILOGO TEST AUTENTICAZIONE")
print(f"{'='*55}")
for cat, count in risultati.items():
    perc = count / n * 100 if n > 0 else 0
    print(f"  {cat:<20} : {count:>4} ({perc:.1f}%)")

if risultati["SICURO (4.01)"] == 0:
    print("\n  [!!!] Nessun endpoint critico implementa 4.01 Unauthorized.")