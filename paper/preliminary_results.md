# Preliminary Results — H1 / H2 / H3 (Kali engine pool)

**100% real data, Kali engines.** Every row in `data/results.csv` is a
live ablation run using a 5-engine pool: nmap (Kali via SSH) +
http_probe (local urllib) + url_crawler (local) + nikto (Kali via SSH)
+ header_vuln_check (local). Slow engines (nuclei, nmap_vuln, sqlmap,
wpscan) run ad-hoc — see `paper/deep_scan_juiceshop.json` for the
full 10-engine deep scan against Juice Shop.

- **Total cells:** 40 (10 targets × 4 conditions × 1 seed)
- **Wall-clock:** 60 min for the matrix
- **Engine pool:** 5 for the matrix, 10 for the deep scan
- **Targets:** juiceshop, bWAPP, commix_testbed, VAmPI, WebGoat, DVWA,
  NoWASP/Mutillidae II, BodgeIt, PyGoat, OWASP-SKF JS-CSRF — all
  reached via the host's LAN IP so Kali SSH engines can scan them too

## Per-target findings table

| Target          | full | no-replan | no-fusion | random-order |
|-----------------|-----:|----------:|----------:|-------------:|
| juiceshop       |   44 |        14 |        44 |           44 |
| bWAPP           |   33 |        14 |        33 |           33 |
| commix_testbed  |   39 |        14 |        39 |           39 |
| VAmPI           |   31 |        14 |        31 |           31 |
| WebGoat         |   28 |        14 |        28 |           28 |
| **DVWA**        | **2033** |    14 |      2033 |         2033 |
| NoWASP          |   40 |        14 |        40 |           40 |
| BodgeIt         |   29 |        14 |        28 |           29 |
| PyGoat          |   25 |        14 |        23 |           30 |
| skf_csrf        |   26 |        14 |        26 |           26 |

DVWA is an outlier — nikto enumerates hundreds of test endpoints
because DVWA exposes everything by design. We report stats both with
and without it.

## H1 — Closed-loop replanning improves coverage
Three tests, same data:

| Test                              | n  | statistic | p-value     | effect size |
|-----------------------------------|----|-----------|-------------|-------------|
| Paired t (all targets)            | 10 | t = 1.09  | 0.151       | d = 0.35    |
| **Wilcoxon signed-rank (all)**    | 10 | W = 55    | **0.001**   | n/a         |
| **Paired t (DVWA excluded)**      |  9 | t = 8.36  | **2 × 10⁻⁵** | **d = 2.79** |

**Mean lift (DVWA excluded):** full = 32.8 vs. no-replan = 14.0
(**+134%**).

The **rank-based** test reaches p < 0.01 across all 10 targets even
with the DVWA outlier, because Wilcoxon cares about the direction of
the difference, not its magnitude. Every target shows full > no-replan;
DVWA just shows a *much* bigger gap than the others.

The **parametric** t-test only reaches significance once DVWA is
removed because the 2019-finding delta inflates the standard
deviation and crushes the t-statistic. For the paper we'd report both.

Figure: [`notebooks/figures/h1_findings_full_vs_no_replan.png`](../notebooks/figures/h1_findings_full_vs_no_replan.png)
(log scale so DVWA doesn't crush the y-axis).

## H2 — Cross-tool fusion no separation on this engine pool

- mean(full) = mean(no-fusion) = 8 of 10 targets
- 2 targets show fusion gain: PyGoat (+2) and BodgeIt (+1)
- Wilcoxon p = 0.250 — not significant

**Honest mechanism**: with the current 5-engine pool, the chain is
shallow. nmap's open_ports inform the chain of *which ports nikto
scans*, but nikto's findings come from its own logic, not from a
fusion-dependent prior step. Severing the Facts() bag doesn't break
anything because nothing downstream strictly requires it.

To get H2 separation:
1. Add a fact-coupled real engine (e.g., a tech_cve_lookup that
   requires `tech_versions` from nmap). Concrete + small.
2. Or wire in nmap_vuln to the matrix (currently ad-hoc): its NSE
   scripts target the open_ports nmap discovered, so fusion off →
   nmap_vuln has no port list → fewer findings.

## H3 — Decision-quality stratification
Stacked-bar across 40 cells (10 targets × 4 conditions):

| Condition    | mean findings | median | mean duration (s) | pct incorrect |
|--------------|--------------:|-------:|------------------:|--------------:|
| full         |        233    |     31 |             154   |         34.3% |
| no-replan    |         14    |     14 |              19   |          0%   |
| no-fusion    |        233    |     31 |             117   |         34.3% |
| random-order |        233    |     31 |             103   |         25.6% |

Mean is dominated by DVWA's 2033; median (the more honest measure
here) shows the typical target's behavior. Per-condition the same
pattern holds:

- no-replan: 0% incorrect, 14 findings, 19s — only the seed engines fire
- full / no-fusion: 34.3% incorrect from the duplicate emission;
  `nikto` produces the bulk of the findings on most targets
- random-order: 25.6% incorrect because shuffling defuses some duplicates

Figure: [`notebooks/figures/h3_decision_quality_stacked.png`](../notebooks/figures/h3_decision_quality_stacked.png)

## Deep scan — 10-engine pool against Juice Shop

`paper/deep_scan_juiceshop.json` is the full output of:
```
nmap → nmap_vuln → nuclei → nikto → http_probe → url_crawler → header_vuln_check
```
running once against http://192.168.1.73:3000 (host LAN IP for Juice
Shop):

- **Duration:** 482s (8 minutes)
- **Engines that fired:** 7 (sqlmap/dalfox/wpscan target_type-filter
  skipped because Juice Shop has no WordPress / no obvious injectable
  params with our crawler)
- **Total findings:** 336 (314 high, 21 info, 1 low)
- **High-severity findings:** 314 — all real CVE matches against
  nginx 1.18.0 (port 80/443) + Apache 2.4.7 (port 8089) + Apache
  Tomcat (port 8080) discovered on the LAN

Sample high-severity findings (real CVE IDs from nmap_vuln NSE
scripts):

```
[high] cpe on port 8089: CVE-2026-44631 (CVSS 9.8)
[high] cpe on port 8089: CVE-2026-28780 (CVSS 9.8)
[high] cpe on port 8089: CVE-2024-38476 (CVSS 9.8)  Apache mod_rewrite SSRF
[high] cpe on port 8089: CVE-2024-38474 (CVSS 9.8)
[high] cpe on port 8089: CVE-2023-25690 (CVSS 9.8)  HTTP request smuggling
[high] cpe on port 8089: CVE-2022-31813 (CVSS 9.8)  mod_proxy_ajp X-Forwarded-For
... +308 more
```

These are real CVEs against the actual Apache 2.4.7 on the test LAN,
detected via nmap NSE scripts running over real SSH against real
Kali. No mock, no synthesis.

## Reproduction

```bash
# Configure the Kali profile (gitignored). Example:
cat > kali_profile.ini <<EOF
[kali]
host = 192.168.1.236
username = kali
auth_method = password
password = <yours>
EOF

# Spin up all 10 labs.
docker run --rm -d -p 3000:3000  --name juice-shop      bkimminich/juice-shop
docker run --rm -d -p 8089:80    --name commix-testbed  commixproject/commix-testbed
docker run --rm -d -p 8080:8080  --name webgoat-lab     webgoat/webgoat:latest
docker run --rm -d -p 8081:80    --name bwapp-lab       raesene/bwapp
docker run --rm -d -p 5002:5000  --name vampi-lab       erev0s/vampi:latest
docker run --rm -d -p 8090:80    --name dvwa-lab        vulnerables/web-dvwa
docker run --rm -d -p 8091:80    --name nowasp-lab      citizenstig/nowasp
docker run --rm -d -p 8093:8080  --name bodgeit-lab     psiinon/bodgeit
docker run --rm -d -p 8094:8000  --name pygoat-lab      pygoat/pygoat:latest
docker run --rm -d -p 8095:5000  --name skf-csrf-lab    blabla1337/owasp-skf-lab:js-csrf
sleep 20

# Run the matrix (10 × 4 × 1 = 40 cells, ~60 min over SSH).
rm -f data/results.csv
python scripts/run_matrix.py --all --kali fast

# Refresh figures + summary.
jupyter nbconvert --to notebook --execute \
    notebooks/h1_h2_h3_analysis.ipynb \
    --output h1_h2_h3_analysis.ipynb
```

## What's next (camera-ready)

1. **Wire nmap_vuln + nuclei into the matrix** (currently ad-hoc).
   This pushes per-cell time from 3 min to ~8 min, so the full matrix
   moves to ~5 hours. Run overnight.
2. **Scale targets** — proposal says 30+. Easy paths: 5+ more Docker
   labs (Hackazon, NodeGoat, Vulnado, OWASP-SKF micro-labs), the HTB
   Starting Point queue, VulnHub VMs.
3. **LLM planner across the matrix** — Claude/GPT-4 paid replans
   instead of HeuristicPlanner. Compare LLM vs heuristic incorrect
   rate (H3).
4. **Human-expert baselines** for 3 representative targets — record
   via `python -m reasonchain.human_baseline …`.
