"""
mappa_mondiale.py
=================
Distribuzione geografica del campione tramite geolocalizzazione IP.

Interroga l'API ip-api.com in batch (max 100 IP per chiamata) e
genera un grafico a barre delle top 10 nazioni per numero di host.

Input  : risultati_massivi_shodan.csv
Output : Grafico_Mappa.png
Autore : Camilla Vivaldi 
Corso  : Network Security – Università degli Studi di Verona
Data   : 10 Maggio 2026
"""

import time
import pandas as pd
import requests
import matplotlib.pyplot as plt

FILE_INPUT   = "risultati_massivi_shodan.csv"
BATCH_SIZE   = 100   # limite dell'API ip-api.com per chiamata batch
PAUSA_SEC    = 2     # pausa di cortesia tra un batch e il successivo

print("[*] Caricamento dataset...")
df = pd.read_csv(FILE_INPUT)
ip_unici = df.iloc[:, 0].dropna().unique().tolist()
print(f"[*] IP unici da geolocalizzare: {len(ip_unici)}\n")

nazioni = []

for i in range(0, len(ip_unici), BATCH_SIZE):
    batch = ip_unici[i:i + BATCH_SIZE]
    print(f"[*] Batch {i//BATCH_SIZE + 1}: {len(batch)} IP...", end=" ")

    try:
        risposta = requests.post("http://ip-api.com/batch", json=batch, timeout=10)
        if risposta.status_code == 200:
            for info in risposta.json():
                if info.get("status") == "success":
                    nazioni.append(info.get("country", "Sconosciuta"))
            print(f"OK ({len(nazioni)} nazioni raccolte finora)")
        else:
            print(f"Errore HTTP {risposta.status_code}")
    except Exception as e:
        print(f"Errore connessione: {e}")

    time.sleep(PAUSA_SEC)

if not nazioni:
    print("[ERRORE] Nessuna nazione raccolta. Controlla la connessione.")
    exit()

# ── Statistiche ───────────────────────────────────────────────────────────────

top10 = pd.Series(nazioni).value_counts().head(10)

print("\n[*] Top 10 nazioni per numero di host:")
for nazione, count in top10.items():
    perc = count / len(nazioni) * 100
    print(f"    {nazione:<20} : {count:>4} host ({perc:.1f}%)")

# ── Grafico ───────────────────────────────────────────────────────────────────

plt.figure(figsize=(10, 6))
top10.plot(kind="bar", color="#4e79a7", edgecolor="black")
plt.title("Top 10 nazioni – dispositivi CoAP esposti su Internet")
plt.xlabel("Nazione")
plt.ylabel("Numero di host")
plt.xticks(rotation=45, ha="right")
plt.grid(axis="y", alpha=0.4)
plt.tight_layout()
plt.savefig("Grafico_Mappa.png", dpi=150)
plt.close()
print("\n[+] Salvato: Grafico_Mappa.png")