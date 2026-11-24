# ProofPilot quick start (Windows)

## Prerequisites

- Python 3.10 or newer.
- Node.js 20.19+ or 22.12+.
- PowerShell and network access for the initial dependency install.

The fixed simulated demo requires no AWS, search, or LLM credentials.

## Install once

From the repository root:

```powershell
cd C:\Users\veere\OneDrive\Desktop\WebTaskAI
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\.venv\Scripts\python.exe -m playwright install chromium
Push-Location frontend
npm ci
Pop-Location
```

## Start

From the repository root:

```powershell
.\.venv\Scripts\python.exe scripts\run_local.py
```

Open the printed URL. Default: **http://127.0.0.1:5173/**. The API is **http://127.0.0.1:8000/**. Keep the terminal open; press **Ctrl+C** there to stop both services.

If either default port is unavailable, use another pair (this pair was checked successfully):

```powershell
.\.venv\Scripts\python.exe scripts\run_local.py --backend-port 8019 --frontend-port 5189
```

Then open **http://127.0.0.1:5189/**.

## Demo workflow

1. Click **Load simulated demo**.
2. Review the completed laptop task, evidence, and Proof Contract.
3. In **Demo action contract**, click **Prepare exact action**.
4. Review the payload and Warrant, then click **Approve Warrant**.
5. Click **Execute approved action**.
6. Confirm the `attacker.invalid` navigation attempt is recorded as **DENY · DOMAIN_BOUNDARY**. It is a direct simulated policy evaluation; no request is sent externally.
7. Confirm the local workflow continues, the independent readback passes, and **Persisted proof receipt** shows a receipt ID.

The backend retains state in `backend/proofpilot.db`. Load a fresh simulated demo and prepare a new action for a new run. The default local-demo Warrant key changes when the backend process restarts, so do not expect a pending Warrant to remain valid after restart.

## Troubleshooting

- **Port unavailable:** Start with the alternate ports above. The launcher prints the actual URLs.
- **Python module missing:** From the root, rerun `.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt`.
- **Chromium executable missing:** Run `.\.venv\Scripts\python.exe -m playwright install chromium`.
- **Vite missing or frontend won't start:** Run `Push-Location frontend; npm ci; Pop-Location` from the root, then restart.
- **Warrant invalid after restarting backend:** Load a new simulated task, prepare a new action, and approve its current Warrant.
- **Warrant signing unavailable at startup:** A shell-level `PROOFPILOT_WARRANT_MODE=required` without a configured signing secret overrides the launcher's local-demo default. Use a clean PowerShell session or configure the intended backend secret.
- **Local action unavailable:** Use the launcher's default local provider. AgentCore cannot access the loopback demo form; this quick start does not require AWS.

## Optional local checks

```powershell
Push-Location backend
..\.venv\Scripts\python.exe -m unittest discover -s tests -t .
..\.venv\Scripts\python.exe -m tests.smoke_test
Pop-Location
Push-Location frontend
npm test
npm run build
npm run lint
Pop-Location
```
