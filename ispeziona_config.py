"""
ispeziona_config.py
===================
Resource Discovery approfondito sull'ecosistema And-Link.

Per ogni host con impronta /qlink/ nel dataset, interroga
/.well-known/core e stampa la mappa completa delle API esposte,
verificando quali endpoint rispondono senza autenticazione.

Input  : risultati_massivi_shodan.csv
Autore : Camilla Vivaldi
Corso  : Network Security – Università degli Studi di Verona
Data   : 10 Maggio 2026
"""

import time
import pandas as pd
from coapthon.client.helperclient import HelperClient

FILE_INPUT = "risultati_massivi_shodan.csv"
CAMPIONE   = 20
TIMEOUT    = 4
PORTA      = 5683


def resource_discovery(ip):
    """Interroga /.well-known/core e restituisce il payload grezzo."""
    client = HelperClient(server=(ip, PORTA))
    try:
        res = client.get("/.well-known/core", timeout=TIMEOUT)
        if res and res.payload:
            return res.payload
        return None
    except Exception:
        return None
    finally:
        client.stop()


def testa_endpoint(ip, percorso):
    """GET su un singolo endpoint, restituisce (codice, payload)."""
    client = HelperClient(server=(ip, PORTA))
    try:
        res = client.get(percorso, timeout=TIMEOUT)
        if res is None:
            return None, None
        return str(res.code), res.payload
    except Exception:
        return None, None
    finally:
        client.stop()


print("[*] Caricamento dataset...")
df = pd.read_csv(FILE_INPUT)

# Selezioniamo host con impronta And-Link non ancora visti
maschera = df["Percorso"].str.contains("qlink|apdevice", case=False, na=False)
target = (
    df[maschera]
    .drop_duplicates(subset=["IP Target"])
    .head(CAMPIONE)
)
print(f"[*] Host And-Link selezionati: {len(target)}\n")

for _, row in target.iterrows():
    ip = row["IP Target"]
    print(f"{'='*55}")
    print(f"[*] Richiesta mappa risorse a {ip}...")

    payload = resource_discovery(ip)

    if not payload:
        print("    [!] Nessuna risposta da /.well-known/core")
        continue

    print(f"    [!!!] MAPPA RICEVUTA:")

    # Parsing manuale del CoRE Link Format
    import re
    risorse = re.findall(r"<([^>]+)>", payload)

    for percorso in risorse:
        codice, dati = testa_endpoint(ip, percorso)

        if codice is None:
            stato = "TIMEOUT"
        elif "2." in codice or codice == "69":
            stato = "APERTO (2.05)"
        elif "4.01" in codice or codice == "129":
            stato = "PROTETTO (4.01)"
        else:
            stato = f"ALTRO ({codice})"

        print(f"    -> {percorso:<45} {stato}")

        # Se l'endpoint è aperto mostriamo un estratto del payload
        if dati and "APERTO" in stato:
            estratto = dati[:100] + "..." if len(dati) > 100 else dati
            print(f"       [DATA]: {estratto}")

    time.sleep(1)

print(f"\n[*] Ispezione completata.")