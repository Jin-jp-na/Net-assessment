# RiskLens acceptance test checklist

This checklist covers the features implemented in [backend/main.py](backend/main.py), including its scanner modules. These are test instructions, not recorded passes. Live lab tests have not been executed. Use an isolated lab you control; result views also perform credential login attempts.

## Setup and test inputs

- Start the backend and open its UI. Examples assume `http://127.0.0.1:8000`; substitute your actual backend port.
- Lab A: a Metasploitable 2 VM on host-only networking. Find its address inside the VM using `ifconfig`. Replace the example `192.168.56.101` everywhere with that address.
- Lab B: a controlled HTTP service on port 8080. Configure `/admin` and `/login` as real paths, unknown paths as 404, and initially omit all six security headers listed below. Configure `/secure` to return 401 plus `WWW-Authenticate: Basic` unless correct credentials are supplied.
- For deterministic credential testing, use a disposable lab-only account `root` / `root`, the first candidate in the current credential list. Default Metasploitable credentials do not guarantee detection. HTTP Basic is the simplest controlled case; SSH/FTP require services that permit the test account.
- Lab C: an HTTPS endpoint with a valid certificate, plus a separate self-signed endpoint. Use hostnames matching their certificates.
- Record scan ID, target, profile, ports, outcome, and evidence. Reuse completed scans for result/export checks rather than repeating a full scan for every row.

| Run | Target (replace example IP) | Profile | Ports | Exposure |
|---|---|---|---|---|
| Smoke | `192.168.56.101` | `quick` | `80` | `internal` |
| Network | `192.168.56.101` | `full` | `21,22,23,25,80,139,445,3306,5432,5900,6667` | `internal` |
| Controlled web | `http://192.168.56.101:8080` | `web` | `8080` | `internal` |
| TLS | Your HTTPS lab URL with explicit port | `web` | That port | `internal` |

The controlled web service may run on another host; substitute its address. Do not assume Metasploitable already has that web configuration.

## Scan creation and lifecycle

| ID | Action | Expected result / pass criterion |
|---|---|---|
| S01 | Open `/health`, then `/`. | Health reports `ok` and a boot ID; UI loads. |
| S02 | Run Smoke. | Only requested port scanned; Gobuster skipped; scan completes. Quick mode does not request version detection. |
| S03 | Run Network with `standard`, then `full`. | Standard requests service detection; full adds OS detection and vulnerability scripts. Verify raw XML rather than expecting a fixed CVE count. |
| S04 | Scan `http://LAB_IP:8080` with ports blank. | Nmap and HTTP checks use port 8080. |
| S05 | Submit a target containing `:8080` with explicit ports `80`. | Explicit ports win; network/web checks use 80. |
| S06 | Scan a small host-only CIDR containing your lab, port 80. | Angry IP discovery is shown before Nmap; alive-host output matches discovery; Gobuster skipped. Use your actual isolated subnet. |
| S07 | Scan a lab subnet with no responding hosts. | Discovery terminates with a no-host/failure message, not endless running. Discovery process timeout is 300 seconds. |
| S08 | Mock a hanging Nmap process. | Either runner fails at the configured 600-second limit, removes temporary XML, and remains failed when polled. |
| S09 | Restart backend during an active test scan. | Persisted unfinished scan becomes failed with interruption message; completed history remains completed. External-process cleanup is not guaranteed. |
| S10 | Poll while Nmap writes temporary output. | Remains running; incomplete XML is not published as completed output. |
| S11 | Mock standard-mode Nmap failure. | One attempt; scan fails. OS-enabled commands may retry without OS detection within the original timeout budget. |

## Findings and negative controls

| ID | Setup/action | Expected result / pass criterion |
|---|---|---|
| F01 | Inspect `/scan/ID/parsed` for Network. | Open lab ports have correct protocol, service, and available product/version. Missing version data alone is not failure. |
| F02 | Inspect raw XML and findings for a known applicable NSE vulnerability check. | Script ID/evidence appear. Manually confirm evidence reports a vulnerability rather than an error or negative verdict; current implementation does not distinguish these. |
| F03 | Test a patched service or NSE negative/error response. | Acceptance requirement: no confirmed vulnerability from negative/error output. Current code may fail because all nonempty port-script output becomes high-severity findings. |
| F04 | Enable lab HTTP Basic `root` / `root` at `/secure`; request findings. | Critical Credential check finding. Independently verify those credentials authenticate. |
| F05 | Change account to a password absent from tested candidates; request findings again. | No confirmed weak-credential finding. This establishes no tested match, not that all credentials are strong. |
| F06 | Return 403 or 500 for wrong Basic credentials. | Acceptance requirement: no successful-login finding. Current code treats any non-401 response as success, a known false-positive case. |
| F07 | Repeat F04/F05 on configured lab SSH and FTP. | Accepted login produces critical finding; rejected login does not. Services must permit the test account. |
| F08 | Inspect `/scan/ID/nvd` for an identified vulnerable product/version. | Keyword/CVE metadata appear if NVD returns matches. Verify applicability against installed version; keyword matches are not exploitation proof. No fixed live CVE count. |
| F09 | Mock NVD failure or missing product identification. | No fabricated CVEs; failed lookup carries error and empty CVE list; other results remain usable. |
| F10 | Scan Lab B without all six security headers. | Six missing checks and six medium HTTP-assessment findings. |
| F11 | Add all six headers and start a fresh scan. | Checks pass; missing-header findings disappear. Current implementation checks presence, not policy quality. |
| F12 | Compare Basic authentication with an HTML login form. | Basic authentication checked; form-based login unsupported. Undetected form passwords are not coverage. |
| F13 | Inspect findings summary/order. | Counts match severity rows; sorted by severity then numeric CVSS descending. |

Headers for F10/F11: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. Configure appropriate policies. Current code checks HSTS even on HTTP; presence does not prove effective HTTPS enforcement.

## Web scanning, risk, reports, and errors

| ID | Action | Expected result / pass criterion |
|---|---|---|
| W01 | Scan Lab B; inspect `/webscan/ID/results`. | Known paths in Gobuster's wordlist appear with correct statuses; unknown 404 paths are not discoveries. |
| W02 | Return identical 200 responses for unknown paths. | Useful wildcard warning/failure, not endless spinner. Check web-scan status separately from overall status. |
| W03 | Scan a closed HTTP port on your lab host. | Explained connection failure and terminal web status. HTTP-to-HTTPS fallback can extend duration. |
| W04 | Scan valid HTTPS, then self-signed HTTPS. | TLS protocol/cipher available where supported; certificate validation failure is a review item. Unverified fallback is not certificate validation success. |
| R01 | Score identical service data as internal/external. | External score no lower; range 0–100. SSH/22 fixture without CVEs or confirmed weak credentials: internal 65/high; external 90/critical. |
| R02 | Inspect `/scan/ID/attack-graph`. | Consistent host/service/CVE nodes and references; no duplicate node IDs. `possible_chain` edges are heuristic, not exploit proof. |
| R03 | Download `/scan/ID/findings.csv`. | Opens and matches findings fields/counts for stable lab data; multiline evidence remains in one quoted row. Enrichment reruns can change results if services change. |
| R04 | Download `/scan/ID/report.pdf`. | Opens with correct scan/services. Compare UI/CSV: known gap is PDF findings omit web assessment, so missing-header findings may be absent. |
| R06 | Restart after completed scans; open history. | Completed records and IDs persist. |
| R07 | POST `/scans/clear` after saving evidence, with no active scans. | Metadata/history clears; raw files remain. This intentionally clears test history. |
| E01 | POST `/scan` with empty target. | HTTP 400, Target is required. Missing target field returns 422. |
| E02 | Request status/raw/parsed/findings for nonexistent scan ID. | HTTP 404, not unhandled error. |
| E03 | Request results while Nmap runs. | Unavailable output returns 404; status preserves actual stage. |
| E04 | Submit invalid port text or hostname. | Record behavior. Acceptance goal: helpful validation/failure, no endless running. Current API does not thoroughly validate before Nmap. |

## Repeatable API example

Replace the IP with your lab target before running. This starts a scan:

```powershell
$api = 'http://127.0.0.1:8000'
$body = @{
    target = '192.168.56.101'
    profile = 'full'
    ports = '21,22,80,139,445,3306'
    exposure = 'internal'
    description = 'Acceptance test: isolated lab'
} | ConvertTo-Json
$scan = Invoke-RestMethod -Method Post -Uri "$api/scan" -ContentType 'application/json' -Body $body
$scanId = $scan.scan_id
Invoke-RestMethod "$api/scan/$scanId"
```

Repeat the status command until completed or failed. After completion:

```powershell
Invoke-RestMethod "$api/scan/$scanId/parsed"
Invoke-RestMethod "$api/scan/$scanId/findings" | ConvertTo-Json -Depth 15
Invoke-RestMethod "$api/webscan/$scanId/assessment" | ConvertTo-Json -Depth 10
Invoke-WebRequest "$api/scan/$scanId/findings.csv" -OutFile 'test-findings.csv'
Invoke-WebRequest "$api/scan/$scanId/report.pdf" -OutFile 'test-report.pdf'
```

Assessment is unavailable if web scanning was skipped or no audit was produced. Findings/exports can take longer because they rerun NVD lookups and credential checks.

## Existing automated regression tests

From project root, using your configured Python environment:

```powershell
python -B -m unittest discover -s tests -v
```

[tests/test_scan_lifecycle.py](tests/test_scan_lifecycle.py) contains five mocked tests: discovery status, timeout cleanup for both runners, no redundant standard retry, atomic publication, and restart recovery. These do not perform live scans or establish end-to-end findings coverage.

## Current coverage limits

- `web` profile runs Nmap service detection before web checks.
- Multi-host runner always requests OS detection and vulnerability scripts regardless of requested profile.
- Credential checks try at most 200 generated candidates per protocol check. Username-major generation and a large password list can focus those attempts on the first username.
- Overall completion can overwrite failed Gobuster status; retain `/webscan/ID` evidence for web failures.
- No single target guarantees every finding. Deterministic automated coverage needs fixtures/mocks for CVEs, NSE positive/negative/error output, authentication responses, TLS errors, and subprocess failures.
- TLS review items and Gobuster paths are not all unified findings. SQL injection, XSS, form authentication, and general authenticated application scanning are not comprehensively implemented.

## Result log

| Test ID | Scan ID / fixture | Expected | Actual | Pass / Fail / Blocked | Evidence |
|---|---|---|---|---|---|
| S01 | | | | | |
