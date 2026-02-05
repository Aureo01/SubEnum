#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import httpx
from tqdm.asyncio import tqdm

console = Console()

# These are the passive sources
SOURCES = {
    "crtsh": "https://crt.sh/?q=%25.{domain}&output=json",
    "alienvault": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "hackertarget": "https://api.hackertarget.com/hostsearch/?q={domain}",
    "threatminer": "https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
}

async def fetch_crtsh(client, domain):
    subdomains = set()
    try:
        resp = await client.get(SOURCES["crtsh"].format(domain=domain))
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    if line.endswith(f".{domain}") and "*" not in line:
                        subdomains.add(line.lower().strip())
    except Exception:
        pass
    return subdomains

async def fetch_alienvault(client, domain):
    subdomains = set()
    try:
        resp = await client.get(SOURCES["alienvault"].format(domain=domain))
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "")
                if hostname.endswith(f".{domain}") and "*" not in hostname:
                    subdomains.add(hostname.lower().strip())
    except Exception:
        pass
    return subdomains

async def fetch_hackertarget(client, domain):
    subdomains = set()
    try:
        resp = await client.get(SOURCES["hackertarget"].format(domain=domain))
        if resp.status_code == 200 and "No results" not in resp.text:
            for line in resp.text.splitlines():
                if line:
                    subdomain = line.split(",")[0]
                    if subdomain.endswith(f".{domain}"):
                        subdomains.add(subdomain.lower().strip())
    except Exception:
        pass
    return subdomains

async def fetch_threatminer(client, domain):
    subdomains = set()
    try:
        resp = await client.get(SOURCES["threatminer"].format(domain=domain))
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("results", []):
                hostname = entry.get("hostname", "")
                if hostname.endswith(f".{domain}") and "*" not in hostname:
                    subdomains.add(hostname.lower().strip())
    except Exception:
        pass
    return subdomains

async def enumerate_subdomains(domain, timeout=10):
    subdomains = set()
    limits = httpx.Limits(max_connections=20)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; SubEnum/1.0)"}
    async with httpx.AsyncClient(limits=limits, timeout=timeout, headers=headers) as client:
        tasks = [
            fetch_crtsh(client, domain),
            fetch_alienvault(client, domain),
            fetch_hackertarget(client, domain),
            fetch_threatminer(client, domain),
        ]
        results = await tqdm.gather(*tasks, desc="🔍 Looking for subdomains...", disable=None)
        for result in results:
            subdomains.update(result)
    return sorted(subdomains)

def print_results_table(subdomains, domain):
    table = Table(title=f"Subdomains found for {domain}", show_header=True, header_style="bold cyan")
    table.add_column("Subdomain", style="magenta")
    table.add_column("Status", style="green")

    for sub in subdomains:
        table.add_row(sub, "✅")

    console.print(table)

def save_results(subdomains, domain, output_dir="subenum_results"):
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.join(output_dir, f"subenum_{domain}")

    with open(f"{base_name}.txt", "w") as f:
        for sub in subdomains:
            f.write(sub + "\n")

    with open(f"{base_name}_stats.json", "w") as f:
        json.dump({
            "domain": domain,
            "total_subdomains": len(subdomains),
            "subdomains": list(subdomains)
        }, f, indent=2)

    console.print(f"📥 All results saved to: {output_dir}/")

def print_summary(subdomains, domain):
    panel = Panel(
        f"""
📊 Quick summary:
  - Target domain: {domain}
  - Subdomains found: {len(subdomains)}
        """,
        title="SubEnum - Summary",
        expand=False
    )
    console.print(panel)

def main():
    parser = argparse.ArgumentParser(description="Passive subdomain enumeration without touching the target")
    parser.add_argument("domain", help="Target domain (example: example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout per request (seconds)")
    parser.add_argument("--output-dir", default="subenum_results", help="Where results will be saved")
    args = parser.parse_args()

    domain = args.domain.lower().strip().rstrip('.')
    console.print(f"[blue]🔍 Enumerating subdomains for {domain}[/blue]")

    subdomains = asyncio.run(enumerate_subdomains(domain, timeout=args.timeout))

    if subdomains:
        print_results_table(subdomains, domain)
        print_summary(subdomains, domain)
        save_results(subdomains, domain, output_dir=args.output_dir)
    else:
        console.print("[yellow]⚠️  No subdomains found for this domain.[/yellow]")

if __name__ == "__main__":
    main()
