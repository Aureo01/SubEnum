# SubEnum 

SubEnum is a **lightweight, passive, no-nonsense** subdomain enumerator.  
I built it with one clear idea in mind: **fast recon, low resource usage, zero noise**.

No brute force.  
No touching the target.  
No private APIs or weird API keys.

Just passive sources, clean results, and a tool you can run almost anywhere.

It works great on:
- Small VPS
- Old laptops
- Virtual machines
- And yeah… even low-power devices if needed

---

## Why does this exist?

Because a lot of recon tools today are:
- Heavy
- Overcomplicated
- Or designed like everyone has unlimited CPU and RAM

SubEnum does **one thing**, and it does it well:  
collect known subdomains from public passive sources and leave them ready for the next step.

If you want:
- Speed
- Portability
- Low footprint
- Clean output

This tool is for you.

---

## How it works

SubEnum pulls data from **passive sources** like:
- crt.sh  
- AlienVault OTX  
- HackerTarget  
- ThreatMiner  

All requests are asynchronous, fast, and respectful.

No scanning.  
No brute forcing.  
No noise.

---

## Usage

```bash
python3 subenum.py example.com

With options:
python3 subenum.py example.com --timeout 10 --output-dir results

---

Output

Results are saved in a simple structure:

subenum_example.com.txt → clean list of subdomains

subenum_example.com_stats.json → basic stats for automation or chaining

Perfect to pipe into:

httpx
nuclei
fuzzers
or whatever your workflow looks like 

