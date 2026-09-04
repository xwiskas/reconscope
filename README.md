# ReconScope Backend

**A local, browser-based ethical-hacking reconnaissance learning workbench.**

ReconScope helps someone new to recon perform *and understand* the reconnaissance phase of ethical hacking: it runs real, proven tools behind a friendly GUI, explains every action in plain language, and enforces strict authorization/scope controls so you can only actively probe targets you have declared and attested you are allowed to test.

> **This is a reconnaissance and enumeration tool only.** It does not exploit, disrupt, deliver payloads, or guess credentials. See [docs/PRD.md](../docs/PRD.md) for the full product specification.

---

## Quick Start

Get ReconScope running in under 2 minutes:

### Option A — Local dev (recommended for contributors)

```bash
# 1. Install Nmap (required for active scanning)
winget install --id Insecure.Nmap --accept-source-agreements --accept-package-agreements

# 2. Clone and enter the backend
git clone https://github.com/xwiskas/reconscope.git
cd reconscope

# 3. Create venv and install
python -m venv .venv
.venv\Scripts\Activate.ps1      # PowerShell
# source .venv/Scripts/activate  # Git Bash / WSL
pip install -e ".[dev]"

# 4. Run the test suite (validates the safety boundary — core feature)
pytest -q

# 5. Launch the app
python -m reconscope.launcher

# 6. Open the printed bootstrap URL in your browser
#    http://127.0.0.1:<port>/#bootstrap=<token>
```

### Option B — Download ZIP (no git)

```bash
# 1. Download from GitHub: https://github.com/xwiskas/reconscope/archive/refs/heads/master.zip
# 2. Extract the ZIP
# 4. Continue from step 3 in Option A (venv, install, test, run)
```

### Option C — GitHub Codespaces (run in browser, zero local setup)

1. Go to [github.com/xwiskas/reconscope](https://github.com/xwiskas/reconscope)
2. Click **Code ▸ Codespaces ▸ Create codespace on master**
3. Wait ~2 min for the dev container to build
4. In the terminal: `cd backend && pip install -e ".[dev]" && pytest -q && python -m reconscope.launcher`
5. Use the **Ports** tab to forward the printed port, then open the bootstrap URL

### Option D — Windows installer (for end users, no Python needed)

If you've built the installer (or download a release):
```powershell
# Build it once:
cd installer
./build.ps1

# Then just run the produced installer:
./dist/ReconScope_Setup.exe
```
This bundles Python, the backend, the React SPA, and Nmap detection into a standalone `.exe` — no Python, venv, or git required on the target machine.

### Option E — PyInstaller one-folder build (portable)

```powershell
cd installer
pyinstaller reconscope.spec
# Output: dist/reconscope/  → copy this folder anywhere, run ReconScope.exe
```

---

**What you'll see (all options):**
- A local FastAPI backend serving a React SPA on loopback only
- One-time bootstrap token flow for session security
- Guided passive recon (RDAP, DNS, CT logs, reverse DNS, asset hints)
- Bounded active recon (TCP scan, service detection, HTTP overview, TLS review) gated by scope
- Live SSE progress + cancel button that kills the scan's process tree
- Markdown reports with evidence traceability, findings, and learner worksheets

---

## Resume Highlights

| Area | What This Project Demonstrates |
|------|--------------------------------|
| **Security Engineering** | Hardened scope enforcement (canonicalization, attestation, gate), loopback-only binding, bootstrap token + CSRF, CSP, subprocess sandboxing (no shell injection), process-tree termination on cancel |
| **Python Backend** | FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic, async/await, dependency injection, background workers, SSE streaming |
| **Testing Discipline** | 100+ pytest tests covering scope bypass prevention, provider failure resilience, restart recovery, process-tree cancellation, port-spec injection prevention, report traceability |
| **Systems Programming** | Subprocess supervision with timeouts/output caps, Nmap XML parsing, process-tree kill on Windows, resource budgets, restart recovery |
| **Frontend Architecture** | React + TypeScript + Vite, SSR-ready build, React Query, live SSE progress, accessible UI (WCAG AA target) |
| **Packaging** | PyInstaller one-folder build, Inno Setup installer, PyInstaller entry point, loopback launcher with bootstrap token |
| **Documentation** | PRD, install/troubleshooting/accessibility guides, ADR-style architecture, module Learning Manifests |

---

## Milestones (PRD §12)

- **M0** — Safety spine: scope canonicalization, evaluation, gate, bootstrap auth, mandatory scope-bypass tests ✅
- **M1** — Passive recon: RDAP, DNS, CT logs, reverse DNS, asset hints, social footprint; evidence store, findings, provider adapters ✅
- **M2** — Bounded active recon: TCP scan, service detection, HTTP overview, TLS review; Nmap XML parsing, subprocess supervisor, live SSE + cancel ✅
- **M3** — Learning, findings, reporting: Markdown reports with evidence traceability, learner worksheets, deterministic recommendations ✅
- **M4** — Windows packaging: PyInstaller + Inno Setup installer ✅ (build scripts ready)

---

## Tech Stack (Fixed — PRD §12.1)

| Layer | Technology |
|-------|------------|
| Backend | Python 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic |
| Frontend | React 18, TypeScript, Vite, React Query, Tailwind CSS |
| Database | SQLite (WAL mode) |
| Active scanner | Nmap (externally installed, not bundled) |
| Build/Install | PyInstaller + Inno Setup |

---

## Safety Model (TL;DR)

Every target decision funnels through **one canonicalization function** (`reconscope.scope.canonical`) so equivalent notations (IPv4/IPv6, CIDR, case, IDNA, IPv4-mapped IPv6) collapse to a single form. Active modules are refused unless:
1. Project has ≥1 enabled scope entry
2. Current authorization attestation exists
3. Target matches an enabled entry

Checks live in the backend — cannot be bypassed by UI, advanced mode, or imported data.

---

## Testing

```bash
cd backend
pytest -q          # Full suite (100+ tests)
pytest -q -k "scope"   # Scope bypass prevention tests
pytest -q -k "active"  # Active workflow tests
pytest -q -k "passive" # Passive workflow tests
pytest -q -k "report"  # Report traceability tests
```

---

## Packaging (Windows)

```bash
cd installer
./build.ps1   # frontend → PyInstaller → Inno Setup installer
```

Outputs a signed `ReconScope_Setup.exe` (requires Inno Setup `ISCC.exe`).

---

## License

Proprietary — see `pyproject.toml`. Educational use encouraged; redistribution requires permission.

---

## Author

**Sebastian Martinez Cruz** — Ethical hacking reconnaissance learning workbench built as a portfolio project demonstrating security engineering, backend architecture, and testing discipline.