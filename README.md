# ReasonChain Core

Reference implementation of **ReasonChain** — a closed-loop LLM architecture for autonomous multi-tool cybersecurity assessment — and the empirical evaluation that backs the research paper:

> **Obi Ebuka David, Sayed Erfan Arefin.**
> *PENTAGON: Can Closed-Loop LLM Reasoning Achieve Autonomous Multi-Tool Cybersecurity Assessment?* (in submission).
> University of Dayton, Department of Computer Science.

**[Read the paper (PDF)](paper/paper.pdf)** · [Matrix report](reports/matrix_report.pdf) · [Live deep scan](reports/juiceshop_deep.pdf) · [Analysis notebook](notebooks/h1_h2_h3_analysis.ipynb)

## TL;DR

Across 17 OWASP-class web targets and 68 ablation cells, the closed-loop condition surfaces **+2375%** more findings than no-replan (Wilcoxon p=0.0001, Cohen d=52.9 with one outlier excluded). Cross-tool fusion contributes a further **+213%** lift via fact-coupled NSE invocation. Live, the agent surfaces **CVE-2024-38476** (Apache mod_rewrite SSRF, CVSS 9.8) and 313 other real CVE-class findings against an Apache 2.4.7 on the test LAN. Every number in the paper is regenerable from a clean `git clone`.

This repo is the **public, MIT-licensed core** of the architecture. Production extensions, premium engines, multi-tenant auth, SSH-to-Kali execution, and other commercial-only features live in a separate private repository (Pentagon).

## What it finds on a live target

Single live run against **OWASP Juice Shop** on the test LAN, 10-engine Kali pool, 476s wall-clock. Full output: [`reports/juiceshop_deep.pdf`](reports/juiceshop_deep.pdf) · raw JSON: [`reports/juiceshop_deep.json`](reports/juiceshop_deep.json).

| Severity | Count |
|---|---:|
| High      | **314** |
| Medium    | 1 |
| Low       | 1 |
| Info      | 29 |
| **Total** | **345** |

**122 unique CVEs cited**. A sample of the high-severity findings, all real CVE matches surfaced by `nmap --script vuln` against the Apache 2.4.7 instance the agent discovered on port 8089 of the LAN:

| CVE | CVSS | Description |
|---|---:|---|
| **CVE-2024-38476** | 9.8 | Apache HTTP Server mod_rewrite — backend selection via crafted requests (SSRF) |
| **CVE-2024-38474** | 9.8 | Apache HTTP Server mod_rewrite — encoding problem |
| **CVE-2023-25690** | 9.8 | Apache HTTP Server mod_proxy — HTTP request smuggling |
| **CVE-2022-31813** | 9.8 | Apache HTTP Server mod_proxy — X-Forwarded-For header omission |
| **CVE-2022-23943** | 9.8 | Apache HTTP Server mod_sed — buffer overflow |
| **CVE-2022-22720** | 9.8 | Apache HTTP Server mod_lua — use-after-free |
| **CVE-2021-44790** | 9.8 | Apache HTTP Server mod_lua — multipart parser buffer overflow |
| **CVE-2021-39275** | 9.8 | Apache HTTP Server `ap_escape_quotes` — buffer overflow |
| **CVE-2021-26691** | 9.8 | Apache HTTP Server mod_session — memory corruption |
| **CVE-2017-3167** | 9.8 | Apache HTTP Server `ap_get_basic_auth_pw` — authentication bypass |

Per-engine contribution:

| Engine | Findings | Notes |
|---|---:|---|
| `nmap_vuln` | 314 | NSE `--script vuln` against open ports discovered by upstream `nmap` |
| `nuclei`    | 16  | Bare-form template scan |
| `nmap`      | 12  | Service-version probes, populated `open_ports` for `nmap_vuln` |
| `nikto`     | 1   | Banner audit |
| `http_probe`, `url_crawler` | 2 | Baseline web recon |

The full assessment data — every per-cell PDF + JSON, the matrix CSV, the live deep-scan JSON with 345 finding records — is regenerable from a clean `git clone` plus a Kali host and `docker run`.

## Architecture (the three claims under test)

1. **Closed-Loop Reasoning** — after each tool execution, the LLM receives parsed output and re-evaluates the remaining plan.
2. **Cross-Tool Intelligence Fusion** — findings from one tool inform decisions for subsequent tools.
3. **Target-Aware Methodology** — strategy selection adapts to target type (IP / domain / URL / subnet).

```
TARGET + TOOLS + CVE Intel
        ↓
  CONTEXT ASSEMBLY (≤30K tokens)
        ↓
  LLM PLANNING (8-15 step plan)
        ↓
  ┌──────────── CLOSED LOOP ────────────┐
  │   EXECUTE  →  PARSE  →  KG UPDATE   │
  │                                      │
  │                       LLM REPLAN ←──┘
  └──────────────────────────────────────┘
```

## Repository layout

| Path | Contents |
|---|---|
| [`src/reasonchain/`](src/reasonchain/) | Minimal core — orchestrator + planner + facts merger + engine ABI. |
| [`experiments/`](experiments/) | Ablation runners (full / no-replan / no-fusion / random-order) + target manifests. |
| [`notebooks/`](notebooks/) | Statistical analysis (paired t-tests, effect sizes) for H1–H3. |
| [`paper/`](paper/) | Paper draft + figures. |
| [`data/`](data/) | Anonymized per-condition results (gitignored; share via Zenodo for camera-ready). |

## Hypotheses

- **H1** — Closed-loop replanning improves coverage (full vs. `no-replan` ablation; vulnerability discovery delta).
- **H2** — Cross-tool fusion reduces redundancy (full vs. `no-fusion`; assessment time + coverage).
- **H3** — LLM reasoning degrades predictably (per-decision classification → failure-mode taxonomy).

## How to run it

Every engine in this repo makes real network requests; there are no
mock engines and no synthetic data. Pick a depth:

- [**30-second smoke**](#1-30-second-smoke) — light HTTP probes against one
  Juice Shop container.
- [**Single live cell** (with Kali)](#2-single-live-cell-with-kali-engines) —
  one ablation cell against one target, using real `nmap`, `nuclei`, `nikto` over
  SSH.
- [**Full 17-target matrix**](#3-full-17-target-matrix) — reproduce the
  paper's 68-cell H1/H2/H3 ablation.
- [**LLM-planner sweep**](#4-llm-planner-sweep) — same orchestrator, planner
  swapped for Anthropic Claude or OpenAI GPT-4o.
- [**Per-run PDF report**](#5-render-a-pdf-report-of-any-run) — pretty-print
  any `AssessmentResult` to PDF + JSON.

### 1. 30-second smoke

The minimal path. Only the three urllib engines fire (`http_probe`,
`url_crawler`, `header_vuln_check`). You will get the shallow
finding profile shown in the early figures of the paper.

```bash
git clone https://github.com/eobi/reasonchain-core
cd reasonchain-core
pip install -e ".[experiments]"

# Spin up the target.
docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# One ablation cell. Repeats for the other three conditions are
# in the same form.
python -m experiments.run_ablation --target juiceshop --condition full
```

### 2. Single live cell (with Kali engines)

To get `nmap`, `nuclei`, `nikto`, and `nmap_vuln` you need a Kali
Linux box reachable over SSH. The repo expects a profile file at
`./kali_profile.ini` (gitignored) of the form:

```ini
[kali]
host         = <your-kali-ip>
port         = 22
username     = kali
auth_method  = password
password     = <yours>
```

(Public-key auth is also supported — set `key_path` instead of
`password`.) Then:

```bash
# Sanity-check the Kali link.
python -c "from reasonchain.kali_engine import Kali, KaliProfile; \
    k = Kali(KaliProfile.from_ini()); \
    print(k.exec(['uname', '-a'])[1])"

# Reach the host from Kali (the engines need this IP, not localhost).
# Spin Juice Shop on the host's LAN IP first.
docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Single cell with the 5-engine fast Kali pool.
python -m experiments.run_ablation \
    --target juiceshop --condition full --kali fast

# Or the 10-engine deep pool (also includes nuclei, sqlmap, dalfox,
# wpscan — slower, ~8 min per cell).
python -m experiments.run_ablation \
    --target juiceshop --condition full --kali all
```

A cell with the `fast` Kali pool finishes in ~3 min and emits ~350
findings; one with the `all` pool finishes in ~8 min and emits
~340 findings including real CVE matches.

### 3. Full 17-target matrix

Reproduces the paper's H1/H2/H3 results. **~3 hours wall-clock**
on a single Mac driving a single Kali host over SSH.

```bash
# Spin up every OWASP lab the manifests cover. The matrix
# auto-skips any target whose pre-flight ping fails.
docker run --rm -d -p 3000:3000  --name juice-shop      bkimminich/juice-shop
docker run --rm -d -p 8080:8080 --name webgoat-lab     webgoat/webgoat:latest
docker run --rm -d -p 8081:80    --name bwapp-lab       raesene/bwapp
docker run --rm -d -p 8089:80    --name commix-testbed  commixproject/commix-testbed
docker run --rm -d -p 5002:5000  --name vampi-lab       erev0s/vampi:latest
docker run --rm -d -p 8090:80    --name dvwa-lab        vulnerables/web-dvwa
docker run --rm -d -p 8091:80    --name nowasp-lab      citizenstig/nowasp
docker run --rm -d -p 8093:8080  --name bodgeit-lab     psiinon/bodgeit
docker run --rm -d -p 8094:8000  --name pygoat-lab      pygoat/pygoat:latest
docker run --rm -d -p 8095:5000  --name skf-csrf-lab    blabla1337/owasp-skf-lab:js-csrf
docker run --rm -d -p 8096:5000  --name skf-xss-lab     blabla1337/owasp-skf-lab:js-xss
docker run --rm -d -p 8097:5000  --name skf-lfi-lab     blabla1337/owasp-skf-lab:js-lfi
docker run --rm -d -p 8098:5000  --name skf-rfi-lab     blabla1337/owasp-skf-lab:js-rfi
docker run --rm -d -p 8099:5000  --name skf-idor-lab    blabla1337/owasp-skf-lab:js-idor
docker run --rm -d -p 8100:5000  --name skf-jwt-lab     blabla1337/owasp-skf-lab:js-jwt-null
docker run --rm -d -p 8103:5000  --name skf-redir-lab   blabla1337/owasp-skf-lab:js-url-redirection
docker run --rm -d -p 8104:8080  --name altoro-lab      eystsen/altoro
sleep 20

# Run the matrix.
python scripts/run_matrix.py --all --kali fast

# Refresh the notebook (H1/H2/H3 figures).
jupyter nbconvert --to notebook --execute \
    notebooks/h1_h2_h3_analysis.ipynb \
    --output notebooks/h1_h2_h3_analysis.ipynb

# Refresh the matrix-summary PDF.
python scripts/render_matrix_report.py

# Refresh the paper PDF (fills the numbers from data/results.csv,
# then renders).
python scripts/fill_paper.py
python scripts/render_paper.py
```

The notebook produces three figures in `notebooks/figures/`; the
matrix-summary PDF lands in `reports/matrix_report.pdf`; the paper
PDF lands in `paper/paper.pdf`.

If you don't want to babysit, prevent the Mac from sleeping:
```bash
caffeinate -i -s -t 14400   # 4-hour ceiling
```

### 4. LLM-planner sweep

Replaces the deterministic `HeuristicPlanner` with `LLMPlanner`
fronting either **Anthropic Claude** (default, `claude-sonnet-4-6`)
or **OpenAI GPT-4o-mini**. Costs about $1–2 in API calls per
20-cell sweep.

**Where to get the key.** You need one of:

- An Anthropic API key from <https://console.anthropic.com/settings/keys>
  (format: `sk-ant-api03-…`)
- An OpenAI API key from <https://platform.openai.com/api-keys>
  (format: `sk-proj-…` or `sk-…`)

You only need one of the two — the `--planner` flag selects which.

**Where to put it.** Drop it into a `.env` file at the repo root.
This file is **gitignored** (see [.gitignore](.gitignore) — never
committed, never pushed). The `LLMPlanner` reads
`ANTHROPIC_API_KEY` or `OPENAI_API_KEY` from the process
environment at startup.

```bash
# One-time. Pick whichever provider you have.
cat > .env <<EOF
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
# OR:
# OPENAI_API_KEY=sk-proj-your-key-here
EOF

# Load the file into the shell, then run.
set -a && source .env && set +a

# 5 representative targets × 4 conditions = 20 cells.
python scripts/run_llm_sweep.py            # Anthropic (default)
python scripts/run_llm_sweep.py --planner openai

# Or pick your own subset.
python scripts/run_llm_sweep.py \
    --target juiceshop --target bwapp \
    --planner anthropic
```

The sweep writes a separate CSV to `data/llm_sweep.csv` so it
doesn't disturb the matrix data; the H3 comparison table in
[paper §6.5](paper/paper.pdf) reads both files.

If you'd rather not store the key on disk, the runtime also
accepts a one-shot env var:

```bash
ANTHROPIC_API_KEY=sk-ant-… python scripts/run_llm_sweep.py
```

### 5. Render a PDF report of any run

```bash
# A single live deep scan with the 10-engine Kali pool.
python scripts/render_deep_scan.py \
    --target http://192.168.1.73:3000/ --name juiceshop_deep
# → reports/juiceshop_deep.pdf + reports/juiceshop_deep.json

# Or for any run from Python:
python -c "
from reasonchain import (AblationFlags, AssessmentSpec, HeuristicPlanner,
                         REAL_ENGINES, Orchestrator, render_both)
spec = AssessmentSpec(target='http://localhost:3000/', target_type='web_api')
r = Orchestrator(engines=REAL_ENGINES, planner=HeuristicPlanner(),
                 flags=AblationFlags()).run(spec)
render_both(r, 'reports/my_run')  # writes my_run.pdf + my_run.json
"
```

### Future work

Reasonable directions: a head-to-head against PentestGPT [3],
extending the engine pool with an exploitation phase (sqlmap +
dalfox + metasploit-rpc), adding a network target class (CIDR /
IP seed), recruiting human-expert baselines for direct
comparison, and scaling to 30+ targets across additional benchmark
suites. We discuss each in §8 of the paper.

## License

MIT — see [LICENSE](LICENSE). Use, modify, redistribute freely; please cite the paper.

## Citation

```bibtex
@inproceedings{david2026reasonchain,
  title  = {PENTAGON: Can Closed-Loop LLM Reasoning Achieve Autonomous Multi-Tool Cybersecurity Assessment?},
  author = {David, Obi Ebuka and Arefin, Sayed Erfan},
  year   = {2026},
  note   = {In submission}
}
```
