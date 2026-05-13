import os
import time
import csv
import requests
from dotenv import load_dotenv

VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"


def load_api_key() -> str:
    load_dotenv()
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        raise SystemExit("ERROR: VT_API_KEY not found. Put it in a .env file.")
    return api_key


def read_ips(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        ips = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    return ips


def vt_lookup_ip(api_key: str, ip: str) -> dict:
    headers = {"x-apikey": api_key}
    url = VT_IP_URL.format(ip)

    try:
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        return {"ip": ip, "error": str(e)}

    data = r.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    verdict = "malicious" if malicious > 0 else "suspicious" if suspicious > 0 else "clean"

    return {
        "ip": ip,
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "country": attrs.get("country", ""),
        "as_owner": attrs.get("as_owner", ""),
        "asn": attrs.get("asn", ""),
        "reputation": attrs.get("reputation", ""),
        "error": "",
    }


def save_csv(path: str, rows: list[dict]) -> None:
    if not rows:
        print("No results to save.")
        return

    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    api_key = load_api_key()

    ips = read_ips("input.txt")
    if not ips:
        raise SystemExit("No IPs found in input.txt")

    results = []
    for i, ip in enumerate(ips, start=1):
        print(f"[{i}/{len(ips)}] Checking {ip} ...")
        results.append(vt_lookup_ip(api_key, ip))

        # Increase to 2–5 seconds if you hit 429 (rate limit)
        time.sleep(1)

    save_csv("vt_results.csv", results)
    print("✅ Done. Saved results to vt_results.csv")


if __name__ == "__main__":
    main()