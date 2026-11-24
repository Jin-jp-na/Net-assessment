# RiskLens

RiskLens is a Windows dashboard for single-host Nmap discovery and reviewing saved scan evidence.

## Setup

Install Python 3.11 or newer and Nmap for Windows. If Nmap is installed outside the default folder, update `NMAP_PATH` in `backend/main.py`.

Run these commands from the project folder in PowerShell.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\run.ps1
```

If PowerShell blocks the script, run `Set-ExecutionPolicy -Scope Process RemoteSigned` in the same window and try again.

## Demo

1. Open [RiskLens](http://127.0.0.1:8787).
2. Enter `127.0.0.1:8787` to check the port the app is running on. You can also enter an IPv4 address or hostname for a system you have permission to scan.
3. Select a scan profile and click **Start scan**. **Full overview** combines service detection and web checks. With a bare host, it scans Nmap’s default ports and checks HTTP on port 80 or HTTPS on port 443. Adding a port limits both checks to that port.
4. Open **Web Results** after a web assessment to see HTTP status, security headers, and TLS details for HTTPS. Add `https://` to the target to check HTTPS. The tab can also display saved directory results.
5. Use **Findings** for evidence and CSV or PDF downloads, or open **History** to revisit a scan.
6. Press **Ctrl+C** in PowerShell to stop the app.
