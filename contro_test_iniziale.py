"""
contro_test_iniziale.py
=======================
Fase 3 della pipeline di analisi CoAP.

Risolve l'ambiguità dei timeout della Fase 1: un host che non risponde
su UDP/5683 può essere protetto da firewall selettivo oppure semplicemente
offline. Combinando ICMP e CoAP si distinguono le due condizioni.

Logica di classificazione:
  ICMP OK  + CoAP 2.05  → Vulnerabile (falso negativo Fase 1)
  ICMP OK  + CoAP 4.04  → Security through Obscurity
  ICMP OK  + Timeout    → Firewall selettivo UDP
  ICMP KO  + Timeout    → Host offline o firewall totale
  qualsiasi + CoAP 4.01 → Autenticazione corretta

Input  : classificazione_dettagliata_sicurezza.csv
Output : risultati_contro_test_icmp.csv
Autore : Camilla Vivaldi 
Corso  : Network Security – Università degli Studi di Verona
Data   : 10 Maggio 2026
"""

import csv
import subprocess
import platform
import pandas as pd
from coapthon.client.helperclient import HelperClient

FILE_INPUT  = "classificazione_dettagliata_sicurezza.csv"
FILE_OUTPUT = "risultati_contro_test_icmp.csv"
TIMEOUT     = 3
PORTA       = 5683


def esegui_ping(ip):
    """Invia un singolo ICMP Echo Request. Restituisce True se l'host risponde."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        risultato = subprocess.run(
            ["ping", param, "1", "-w", "1000", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return risultato.returncode == 0
    except Exception:
        return False


def testa_coap(ip):
    """GET / su porta 5683, restituisce una stringa con la classificazione."""
    client = HelperClient(server=(ip, PORTA))
    try:
        res = client.get("/", timeout=TIMEOUT)
        if res is None:
            return "TIMEOUT_UDP"
        if "2." in str(res.code) or str(res.code) == "69":
            return "2.05_CONTENT"
        if "4.01" in str(res.code) or str(res.code) == "129":
            return "4.01_UNAUTHORIZED"
        if "4.04" in str(res.code) or str(res.code) == "132":
            return "4.04_NOT_FOUND"
        return f"ALTRO_{res.code}"
    except Exception:
        return "TIMEOUT_UDP"
    finally:
        client.stop()


def classifica(ping_ok, coap_stato):
    if coap_stato == "4.01_UNAUTHORIZED":
        return "Autenticazione Corretta (4.01)"
    if coap_stato == "4.04_NOT_FOUND":
        return "Security through Obscurity (4.04)"
    if coap_stato == "2.05_CONTENT":
        return "Vulnerabile (Falso Negativo Fase 1)"
    if ping_ok and coap_stato == "TIMEOUT_UDP":
        return "Firewall Selettivo UDP"
    if not ping_ok and coap_stato == "TIMEOUT_UDP":
        return "Host Offline o Firewall Totale"
    return f"Non classificato ({coap_stato})"


# Carichiamo solo gli host classificati come NO (timeout o altro) nella Fase 1
df = pd.read_csv(FILE_INPUT)
host_no = df[~df["Classificazione"].str.contains("VULNERABILE", na=False)]
ip_lista = host_no["IP Target"].dropna().unique().tolist()

print(f"[*] Host da contro-testare: {len(ip_lista)}\n")

contatori = {
    "Autenticazione Corretta (4.01)":    0,
    "Security through Obscurity (4.04)": 0,
    "Vulnerabile (Falso Negativo Fase 1)": 0,
    "Firewall Selettivo UDP":            0,
    "Host Offline o Firewall Totale":    0,
}

with open(FILE_OUTPUT, mode="w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["IP Target", "ICMP", "CoAP", "Classificazione"])

    for i, ip in enumerate(ip_lista, 1):
        print(f"[{i:04d}/{len(ip_lista)}] {ip}", end=" ... ")

        ping_ok    = esegui_ping(ip)
        coap_stato = testa_coap(ip)
        risultato  = classifica(ping_ok, coap_stato)

        writer.writerow([ip, "OK" if ping_ok else "KO", coap_stato, risultato])
        print(f"ICMP={'OK' if ping_ok else 'KO'} | CoAP={coap_stato} | {risultato}")

        if risultato in contatori:
            contatori[risultato] += 1

n = len(ip_lista)
print(f"\n{'='*60}")
print("  RIEPILOGO CONTRO-TEST")
print(f"{'='*60}")
for cat, count in contatori.items():
    print(f"  {cat:<40} : {count:>4} ({count/n*100:.1f}%)")

if contatori["Autenticazione Corretta (4.01)"] == 0:
    print("\n  [!!!] Nessun host implementa 4.01 Unauthorized.")

print(f"\n[+] Output: {FILE_OUTPUT}")