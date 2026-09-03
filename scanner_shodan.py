"""
scanner_shodan.py
=================
Fase 1 della pipeline di analisi CoAP.

Acquisisce un campione di dispositivi IoT da Shodan, esegue una
scansione attiva su ciascun IP e produce il dataset principale.

Per ogni host:
  - Test 1: GET /              → verifica Access Control sulla radice
  - Test 2: GET /.well-known/core → Resource Discovery (CoRE Link Format)

Output : risultati_massivi_shodan.csv
Autore : Camilla Vivaldi
Corso  : Network Security – Università degli Studi di Verona
Data   : 10 Maggio 2026
"""

import os
import re
import csv
import shodan
from coapthon.client.helperclient import HelperClient

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
QUERY_RICERCA  = 'port:5683 "CoAP"'
LIMITE_IP      = 1000
TIMEOUT        = 2
PORTA          = 5683
FILE_OUTPUT    = "risultati_massivi_shodan.csv"


def classifica_risorsa(percorso):
    p = percorso.lower()
    if any(x in p for x in ["switch", "led", "reboot", "set", "config", "fw"]):
        return "CRITICO / CONTROLLO"
    if any(x in p for x in ["temp", "hum", "sensor", "meter", "val", "data"]):
        return "DATI SENSORI"
    if any(x in p for x in ["device", "info", "ver", "model", "heartbeat"]):
        return "DIAGNOSTICA"
    return "SCONOSCIUTO"


def estrai_risorse(payload):
    return re.findall(r"<([^>]+)>(:[^,]*)?", payload)


def testa_radice(ip):
    client = HelperClient(server=(ip, PORTA))
    try:
        res = client.get("/", timeout=TIMEOUT)
        if res and (str(res.code) == "69" or "2." in str(res.code)):
            return "SI (Aperto)"
        return "NO"
    except Exception:
        return "NO"
    finally:
        client.stop()


def resource_discovery(ip):
    client = HelperClient(server=(ip, PORTA))
    try:
        res = client.get("/.well-known/core", timeout=TIMEOUT)
        if res and res.payload:
            return estrai_risorse(res.payload)
        return []
    except Exception:
        return []
    finally:
        client.stop()


# ── Acquisizione campione da Shodan ───────────────────────────────────────────

if not SHODAN_API_KEY:
    print("[ERRORE] API key Shodan non trovata. Imposta la variabile SHODAN_API_KEY nel file .env")
    exit()

print(f"[*] Query Shodan: '{QUERY_RICERCA}' (limite: {LIMITE_IP} IP)")
api = shodan.Shodan(SHODAN_API_KEY)

try:
    risultati = api.search(QUERY_RICERCA, limit=LIMITE_IP)
    lista_ip  = [r["ip_str"] for r in risultati["matches"]]
    print(f"[+] Estratti {len(lista_ip)} IP — totale globale: {risultati['total']}\n")
except shodan.APIError as e:
    print(f"[ERRORE Shodan] {e}")
    exit()

# ── Scansione attiva ──────────────────────────────────────────────────────────

print(f"[*] Avvio scansione — output in tempo reale su {FILE_OUTPUT}\n")

with open(FILE_OUTPUT, mode="w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["IP Target", "Vulnerabilità Radice (Info Leak)",
                     "Percorso", "Categoria", "Note"])

    for i, ip in enumerate(lista_ip, 1):
        print(f"[{i:04d}/{len(lista_ip)}] {ip}", end=" ... ")

        vuln_radice = testa_radice(ip)
        risorse     = resource_discovery(ip)

        if not risorse:
            categoria = "INFO LEAK" if vuln_radice == "SI (Aperto)" else "N/A"
            writer.writerow([ip, vuln_radice, "/", categoria, ""])
            print(f"radice={vuln_radice} | risorse=0")
        else:
            for percorso, attributi in risorse:
                categoria = classifica_risorsa(percorso)
                writer.writerow([ip, vuln_radice, percorso,
                                 categoria, attributi or ""])
            print(f"radice={vuln_radice} | risorse={len(risorse)}")

print(f"\n[+] Scansione completata. Output: {FILE_OUTPUT}")