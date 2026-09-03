"""
analisi_avanzata.py
===================
Fingerprinting degli ecosistemi vendor dal dataset di resource discovery.

Identifica i vendor tramite prefissi proprietari nei percorsi CoAP e
genera due grafici:
  - Distribuzione degli ecosistemi vendor nel campione
  - Densità della superficie d'attacco (endpoint per host)

Input  : risultati_massivi_shodan.csv
Output : Grafico_Vendor.png, Grafico_Superficie.png
Autore : Camilla Vivaldi
Corso  : Network Security – Università degli Studi di Verona
Data   : 10 Maggio 2026
"""

import pandas as pd
import matplotlib.pyplot as plt

FILE_INPUT = "risultati_massivi_shodan.csv"


def identifica_vendor(percorso):
    p = str(percorso).lower()
    if "qlink" in p or "apdevice" in p: return "And-Link / China Mobile"
    if "ekit" in p:                      return "Ecosistema Ekit"
    if "ndm" in p:                       return "NDM Systems"
    if "uhp" in p:                       return "UHP Networks"
    if "efento" in p:                    return "Efento (sensori BLE)"
    return "Non identificato"


print("[*] Caricamento dataset...")
df = pd.read_csv(FILE_INPUT)
df["Vendor"] = df["Percorso"].apply(identifica_vendor)

# ── Grafico 1: distribuzione vendor ──────────────────────────────────────────

# Un IP può avere più righe: contiamo un IP per vendor una sola volta
vendor_counts = (
    df.drop_duplicates(subset=["IP Target", "Vendor"])["Vendor"]
    .value_counts()
)

print(f"\n[*] Ecosistemi vendor identificati:")
for vendor, count in vendor_counts.items():
    print(f"    {vendor:<30} : {count} host")

plt.figure(figsize=(8, 8))
vendor_counts.plot(
    kind="pie",
    autopct="%1.1f%%",
    colors=["#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f", "#bab0ac"]
)
plt.title("Distribuzione ecosistemi vendor nel campione CoAP")
plt.ylabel("")
plt.tight_layout()
plt.savefig("Grafico_Vendor.png", dpi=150)
plt.close()
print("\n[+] Salvato: Grafico_Vendor.png")

# ── Grafico 2: densità superficie d'attacco ───────────────────────────────────

# Numero di endpoint esposti per ciascun IP (esclusa la radice /)
risorse_per_ip = (
    df[df["Percorso"] != "/"]
    .groupby("IP Target")
    .size()
)

media   = risorse_per_ip.mean()
massimo = risorse_per_ip.max()
print(f"\n[*] Densità superficie d'attacco:")
print(f"    Media endpoint per host : {media:.1f}")
print(f"    Massimo                 : {massimo}")

plt.figure(figsize=(10, 6))
plt.hist(risorse_per_ip, bins=30, color="#4e79a7", edgecolor="black")
plt.title("Densità della superficie d'attacco (endpoint per host)")
plt.xlabel("Numero di endpoint esposti")
plt.ylabel("Numero di host")
plt.axvline(media, color="red", linestyle="--", label=f"Media: {media:.1f}")
plt.legend()
plt.grid(axis="y", alpha=0.4)
plt.tight_layout()
plt.savefig("Grafico_Superficie.png", dpi=150)
plt.close()
print("[+] Salvato: Grafico_Superficie.png")