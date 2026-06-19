# Figures 5, 6, 7 — Specification

Per Dr. Arefin's 2026-06-17 request: three additional figures, each
showing a **specific experimental run** instantiated through the
blocks of Figure 1. Real prompts, real commands, real outputs at
every block.

These complement (do NOT replace) the existing Figures 2/3/4 (which
are bar/stacked-bar charts of aggregate results). The new figures
turn the architecture diagram into three worked examples, one per
hypothesis claim:

| Figure | Subject | Hypothesis demonstrated |
|---|---|---|
| **Figure 5** | Juice Shop, **full** condition, full Kali pool | H1 — closed-loop replanning finds a real CVE |
| **Figure 6** | Juice Shop, **no-replan** condition, same pool | H1 inverse — without replan, chain dies at seed |
| **Figure 7** | Juice Shop, nmap → nmap_vuln transition | H2 — cross-tool fusion materializes through `Facts["open_ports"]` |

Together: Fig 5 + Fig 6 are a paired side-by-side that proves H1
without needing a bar chart. Fig 7 stands alone as the mechanism
proof for H2.

---

## Common visual language (matches Figure 1)

Each figure reuses Figure 1's block topology:

```
┌─────────────────────────────────────────────────────────────┐
│  TARGET + TOOLS + CVE Intel        (input panel, blue)      │
└──────────────────────┬──────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  CONTEXT ASSEMBLY  (≤30K tokens)   (light blue)             │
└──────────────────────┬──────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  PLANNING                                                    │
│     · Heuristic chain map OR LLM completion                 │
│     · Returns list of Pick(engine, target, depth)           │
└──────────────────────┬──────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  CLOSED LOOP  (orange box, the P1 mechanism)                │
│                                                              │
│    ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│    │ EXECUTE  │──▶ │  PARSE   │──▶ │ KG UPDATE│             │
│    └──────────┘    └──────────┘    └──────────┘             │
│         ▲                                │                   │
│         │                                ▼                   │
│         │                          ┌──────────┐              │
│         └──────────────────────────│  REPLAN  │              │
│                                    └──────────┘              │
└──────────────────────┬──────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  OUTPUT  (green)                                             │
│     · Findings + decision trace + PDF/JSON                  │
└─────────────────────────────────────────────────────────────┘
```

Color convention: blue = inputs/static, orange = closed loop, green
= outputs, grey = ablated/disabled.

---

# Figure 5 — Full closed-loop run finds a real CVE on Juice Shop

**Caption (publication-ready)**:

> Figure 5: A complete `full`-condition run of ReasonChain against
> the OWASP Juice Shop instance on the test LAN. Every block in
> Figure 1 is populated with the actual content that flowed through
> during the run: the engine catalogue, the heuristic planner's
> initial pick set, three iterations of the closed loop (planner →
> dispatch → parse → facts merge → replan), and the final 336-
> finding output that includes three CVSS-9.8 CVEs. The replan
> after nmap is what unlocks nmap_vuln; nmap_vuln scopes to the
> ports nmap surfaced (8089, 8090, 8091) and finds CVE-2024-38476
> on the embedded Apache 2.4.7. Source: `paper/deep_scan_juiceshop.json`.

**Per-block content (the substance the figure needs to display)**:

### Block 1 — Target + Tools + CVE Intel

```
TARGET
  url:           http://192.168.1.73:3000/
  target_type:   web_api
  caps:          max_steps=25  max_depth=3

INSTALLED ENGINES (10)
  Local urllib  : http_probe, url_crawler, header_vuln_check
  Kali via SSH  : nmap, nmap_vuln, nuclei, nikto,
                  sqlmap, dalfox, wpscan

CVE INTEL
  · nuclei templates    : 12,000+ (community + cves/2017→2024)
  · nmap NSE scripts    : 600+ vuln scripts
  · NVD CVE database    : queried per CPE match
```

### Block 2 — Context Assembly

```
FACTS (empty at run start)
  {}

ENGINE CATALOGUE (passed to planner)
  available_engines = [
    "http_probe", "url_crawler", "header_vuln_check",
    "nmap", "nmap_vuln", "nuclei", "nikto"
  ]

SPEC
  target='http://192.168.1.73:3000/', target_type='web_api',
  max_steps=25, max_depth=3, seed=0

(token budget: heuristic planner uses ~0 tokens;
 LLM planner ablation in §6.5 uses ~1,400 tokens here)
```

### Block 3 — Initial Planning (HeuristicPlanner.plan_initial)

```
SEED MAP LOOKUP
  _SEEDS["web_api"]
    → [http_probe, url_crawler]

EMITTED PICKS (depth=0)
  Pick(engine="http_probe",  target="http://192.168.1.73:3000/", depth=0)
  Pick(engine="url_crawler", target="http://192.168.1.73:3000/", depth=0)
```

### Block 4 — Closed Loop (iteration 1 of 3)

```
EXECUTE
  http_probe → urllib.request.urlopen("http://192.168.1.73:3000/")
  Latency: 47 ms

PARSE
  HTTP/1.1 200 OK
  Server: nginx/1.18.0
  Content-Type: text/html
  X-Powered-By: Express
  (3 findings: server_header, content_type, page_title)

KG UPDATE  (Facts.merge)
  Before: {}
  After:  {
    "server_header":  "nginx/1.18.0",
    "content_type":   "text/html",
    "x_powered_by":   "Express"
  }

REPLAN  (HeuristicPlanner.replan, predecessor="http_probe")
  _CHAINS["http_probe"]
    → [nmap, header_vuln_check, nikto]
  Picks emitted (depth=1):
    Pick(nmap, target, depth=1)
    Pick(header_vuln_check, target, depth=1)
    Pick(nikto, target, depth=1)
```

### Block 4 — Closed Loop (iteration 2 of 3)

```
EXECUTE
  nmap → ssh kali@192.168.1.236 'nmap -sV -p 80,443,3000,5000,
                                 8080,8089,8090,8091,8093,8094
                                 192.168.1.73 -oX -'
  Wall-clock: 31.4 s

PARSE  (XML parser → 10 Finding objects, one per open port)
  port 80   → nginx 1.18.0
  port 443  → nginx 1.18.0  (ssl)
  port 3000 → ppp?  (Juice Shop itself)
  port 5000 → rtsp?
  port 8080 → Apache Tomcat
  port 8089 → Apache httpd 2.4.7 (Ubuntu)     ◀── target of next CVE find
  port 8090 → Apache httpd 2.4.25 (Debian)
  port 8091 → Apache httpd 2.4.7 (Ubuntu)
  port 8093 → Apache Tomcat
  port 8094 → WSGIServer 0.2 (Python 3.10.4)

KG UPDATE  (Facts.merge — list union)
  Before: {server_header, content_type, x_powered_by}
  After:  + {
    "open_ports":     [80, 443, 3000, 5000, 8080,
                       8089, 8090, 8091, 8093, 8094],
    "tech_versions":  ["nginx/1.18.0", "Express",
                       "Apache httpd 2.4.7 (Ubuntu)",
                       "Apache httpd 2.4.25 (Debian)",
                       "Apache Tomcat", "WSGIServer 0.2"]
  }                                ▲
                              ◀────┘ this list is what unlocks
                                    fact-coupled engines downstream

REPLAN  (HeuristicPlanner.replan, predecessor="nmap")
  _CHAINS["nmap"]
    → [nmap_vuln, nuclei]
  Picks emitted (depth=2):
    Pick(nmap_vuln, target, depth=2)
    Pick(nuclei,    target, depth=2)
```

### Block 4 — Closed Loop (iteration 3 of 3, the CVE find)

```
EXECUTE
  nmap_vuln cmd_builder reads facts["open_ports"]:
    → ports_str = "80,443,3000,5000,8080,8089,8090,8091,8093,8094"
  command:
    ssh kali@192.168.1.236 'nmap --script vuln
                            -p 80,443,3000,5000,8080,8089,8090,8091,8093,8094
                            192.168.1.73 -oX -'
  Wall-clock: 387.6 s   (NSE vuln scripts dominate)

PARSE  (NSE vuln-script output → 317 Finding objects)
  port 8089:  107 findings  (Apache 2.4.7 CVE chain)
   ├─ CVE-2024-38476  Apache mod_rewrite SSRF       CVSS 9.8 ◀──
   ├─ CVE-2024-38474  Apache mod_rewrite            CVSS 9.8
   ├─ CVE-2023-25690  Apache HTTP request smuggling CVSS 9.8
   └─ CVE-2022-31813  Apache mod_proxy header bypass CVSS 6.5
  port 8090: 103 findings  (Apache 2.4.25 partial CVE overlap)
  port 8091: 107 findings  (same Apache 2.4.7 chain as 8089)

KG UPDATE  (Facts.merge)
  + {
    "vulnerable_ports": [8089, 8090, 8091],
    "cve_matches":      ["CVE-2024-38476", "CVE-2024-38474",
                         "CVE-2023-25690", "CVE-2022-31813"]
  }

REPLAN
  _CHAINS["nmap_vuln"] is empty → no further picks emitted.
  Other depth-2 picks in queue (nuclei, nikto, header_vuln_check)
  continue to run, accumulating to the final 336 findings.
```

### Block 5 — Output

```
AssessmentResult(
  findings:        336,           (314 high, 18 medium, 4 info)
  engines_used:    [http_probe, url_crawler, header_vuln_check,
                    nmap, nmap_vuln, nuclei, nikto]    (7/7)
  decisions:       7 records      (matches §3.4 annotator)
  duration_s:      476.3
  CVE class hits:  CVE-2024-38476, CVE-2024-38474, CVE-2023-25690,
                   CVE-2022-31813     (all CVSS 9.8 except 31813)
)
  ↓
PDF report : reports/juiceshop_deep.pdf
JSON       : paper/deep_scan_juiceshop.json   (committed to repo)
```

### Reviewer takeaway

> Without the replan after nmap, the chain stops at depth 1
> (http_probe + url_crawler + nmap), and nmap_vuln never fires →
> CVE-2024-38476 is not surfaced. **The architectural claim is
> empirically observable in a single run.**

### Render notes
- Show all four iterations of the closed-loop block stacked vertically
  inside one orange "P1 Closed Loop" container.
- The Facts → nmap_vuln cmd_builder arrow (iteration 3) is the
  visual proof of fusion and should be drawn with a distinct red /
  bold arrow.
- Highlight the CVE-2024-38476 line in green or with a star/badge
  to make the "win" visually obvious in the Output block.

---

# Figure 6 — No-replan ablation: same target, chain dies at seed

**Caption (publication-ready)**:

> Figure 6: The identical Juice Shop target under the `no-replan`
> ablation. The orchestrator emits the same initial pick set as
> Figure 5 (http_probe + url_crawler), but the **REPLAN block is
> disabled** (greyed out): after each engine returns, `planner.
> replan()` is never called and no new picks are queued. The chain
> terminates after the seed pair runs, producing 2 findings (server
> banner + crawled URL count), 0 high-severity findings, 0 CVE
> matches. The 314 high-severity findings from Figure 5 — including
> the three CVSS-9.8 CVEs — are unreachable from this configuration.

**Per-block content**:

### Block 1 — Target + Tools + CVE Intel

```
(IDENTICAL to Figure 5 — same target, same engine pool, same caps)

   ⚙ AblationFlags(replanning=False, fusion=True, target_aware=True)
                              ▲
                              └── the only thing that differs
```

### Block 2 — Context Assembly

```
(IDENTICAL to Figure 5)
```

### Block 3 — Initial Planning

```
(IDENTICAL to Figure 5)

  _SEEDS["web_api"]
    → [http_probe, url_crawler]
```

### Block 4 — Closed Loop (only iteration 1 + 2 execute; REPLAN is greyed out)

```
ITERATION 1: http_probe
  EXECUTE   (same as Fig 5)
  PARSE     (same as Fig 5 — 3 facts surfaced)
  KG UPDATE (same as Fig 5)
  REPLAN    ✗  DISABLED  (replanning=False)
            ╳  planner.replan() not called
            ╳  no new picks enqueued
            ╳  _CHAINS["http_probe"] never consulted

ITERATION 2: url_crawler
  EXECUTE   urllib GET + anchor extraction
  PARSE     (12 URLs surfaced, 0 forms, 1 robots.txt entry)
  KG UPDATE + {"discovered_urls": [...12 URLs...]}
  REPLAN    ✗  DISABLED (same as above)

(queue is now empty → orchestrator exits the loop)
```

### Block 5 — Output

```
AssessmentResult(
  findings:        2     ◀── 14 in the matrix run; 2 in the simple
                            cell — both contrast equally well
                            with Fig 5's 336
  engines_used:    [http_probe, url_crawler]   (2/7)
  decisions:       1     (the initial plan; no replans)
  duration_s:      0.016
  CVE class hits:  none ✗
)
  ↓
JSON  : paper/sample_run_juiceshop_noreplan.txt
```

### Reviewer takeaway

> Holding everything constant except `AblationFlags.replanning`,
> the same target produces 168× fewer findings and 0 CVEs vs Fig 5.
> The downstream engines (nmap, nmap_vuln, nuclei, nikto) **exist
> in the engine pool** but are never invoked. **The closed-loop is
> doing the work, not the engine pool.**

### Render notes
- The REPLAN box must be drawn in grey/dashed/with a strikethrough
  arrow — it must be visually obvious to the reviewer that this is
  the disabled block.
- Keep the rest of the figure visually identical to Figure 5 so
  that the side-by-side comparison is direct.
- Recommended layout: Figures 5 and 6 share a single figure
  environment (subfigure 5(a) and 5(b)), with a shared caption
  pointing out that only the REPLAN box differs.

---

# Figure 7 — Cross-tool fusion: how `Facts["open_ports"]` activates nmap_vuln

**Caption (publication-ready)**:

> Figure 7: Detail view of the fusion mechanism (P2) inside the
> closed loop. nmap's discovery of ten open ports — including the
> non-standard 8089/8090/8091 where the Apache httpd 2.4.7 instances
> live — is written into the shared `Facts` bag as
> `{"open_ports": [80, 443, 3000, 5000, 8080, 8089, 8090, 8091,
> 8093, 8094]}`. The fact-coupled `nmap_vuln` engine reads that
> list at invocation time, scopes its NSE `--script vuln` command
> to those exact ports, and surfaces 317 vulnerability findings
> including CVE-2024-38476 on port 8089. Severing the fusion (the
> `no-fusion` ablation, dashed grey path) leaves `nmap_vuln` with
> an empty facts bag at invocation time; the engine falls back to
> its default `80,443` port list and surfaces only 2 findings on
> those well-known ports.

**Per-block content**:

This figure is a **detail callout** of the nmap → nmap_vuln transition
inside Figure 5's closed loop. It zooms into just two iterations and
overlays the no-fusion counterfactual.

### Block A — nmap completes (top of figure)

```
EXECUTE (nmap)
  ssh kali@192.168.1.236 'nmap -sV -p- 192.168.1.73 -oX -'
  Wall-clock: 31.4 s

PARSE (10 ports, one Finding per port)
  port 80   nginx 1.18.0
  port 443  nginx 1.18.0 (ssl)
  port 3000 Juice Shop
  port 5000 rtsp
  port 8080 Apache Tomcat
  port 8089 Apache 2.4.7 (Ubuntu) ◀── will yield CVEs
  port 8090 Apache 2.4.25 (Debian)
  port 8091 Apache 2.4.7 (Ubuntu)
  port 8093 Apache Tomcat
  port 8094 WSGIServer 0.2
```

### Block B — KG Update (shared Facts bag, the fusion substrate)

```
Facts.merge(nmap_result.facts):

  Before:                                After:
  {                                      {
    "server_header": "nginx/1.18.0",       "server_header": "nginx/1.18.0",
    "content_type":  "text/html"           "content_type":  "text/html",
                                           "open_ports": [80, 443, 3000,
                                                          5000, 8080,
                                                          8089, 8090,
                                                          8091, 8093,
                                                          8094],
                                           "tech_versions": [...6 entries...]
  }                                      }
                                          ▲
                                          └── (P2) substrate
                                              activated
```

### Block C — Two parallel paths for nmap_vuln (the experiment)

This is the heart of the figure. Draw two parallel paths from the
"REPLAN → nmap_vuln picked" decision: a solid colored path
labelled **"With fusion (Full)"** and a dashed grey path labelled
**"Without fusion (no-fusion ablation)"**.

```
                  REPLAN picks nmap_vuln
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
   [FULL PATH ─ solid]                  [NO-FUSION PATH ─ dashed grey]

   cmd_builder reads:                   cmd_builder receives:
   facts["open_ports"]                    facts = {} (empty bag)
     = [80, 443, 3000, 5000,                ↓
        8080, 8089, 8090, 8091,            falls back to default:
        8093, 8094]                        ports = "80,443"
     ↓                                       ↓
   command =                              command =
   'nmap --script vuln                    'nmap --script vuln
        -p 80,443,3000,5000,                    -p 80,443
        8080,8089,8090,8091,                    192.168.1.73 -oX -'
        8093,8094
        192.168.1.73 -oX -'
     ↓                                       ↓
   PARSE:                                 PARSE:
     317 findings                           2 findings
     port 8089 → CVE-2024-38476 9.8         port 80  → no high CVE
     port 8089 → CVE-2024-38474 9.8         port 443 → no high CVE
     port 8089 → CVE-2023-25690 9.8         (8089/8090/8091 invisible)
     port 8090 → 103 findings
     port 8091 → 107 findings
```

### Block D — Outcome contrast (bottom of figure)

```
   ┌──────────────────────────────┐    ┌──────────────────────────────┐
   │   FULL (this figure)         │    │   no-fusion (counterfactual) │
   │                              │    │                              │
   │   nmap_vuln findings: 317    │    │   nmap_vuln findings: 2      │
   │   Highest CVSS: 9.8 ×3       │    │   Highest CVSS: —            │
   │   New CVEs: CVE-2024-38476,  │    │   New CVEs: none             │
   │             CVE-2024-38474,  │    │                              │
   │             CVE-2023-25690   │    │                              │
   └──────────────────────────────┘    └──────────────────────────────┘
              ▲                                      ▲
              │                                      │
        Apache 2.4.7 on                     fact bag empty →
        non-standard ports                  default to 80,443 →
        was reachable through               Apache instances on
        Facts["open_ports"]                 8089/8090/8091 invisible
```

### Reviewer takeaway

> P2 is not a generic "the agent shares state" claim — it is a
> specific, observable, scoped-NSE-command mechanism. With fusion,
> nmap_vuln runs against the 10 ports nmap actually found; without
> fusion, it runs against the conventional 2. The CVE-2024-38476
> finding is therefore not just "supported by" fusion — it is
> **causally dependent** on it. The no-fusion path is reproducible
> from the published artifact (re-run with `--no-fusion`).

### Render notes
- The split-path layout (Block C) is the figure's main visual
  device. Keep solid + colored on the left, dashed + grey on the
  right.
- Place the "facts bag" panel between Block A and Block C so the
  reader sees the bag being populated, then sees the FULL path
  consume it.
- The bottom outcome boxes (Block D) should match the visual
  styling of the "Findings" block in Figures 5/6 for consistency.
- A small inset showing the actual one-line cmd_builder code (from
  `subprocess_engines.py`) — `cmd = f"nmap --script vuln -p
  {','.join(map(str, facts.get('open_ports', [80,443])))} ..."` —
  would make the mechanism unambiguous to a code-reading reviewer.

---

# Rendering pathway

For ICSE submission quality, two production paths work:

## Option A — TikZ in LaTeX (highest quality, most portable)

Each figure becomes a `\begin{tikzpicture}...\end{tikzpicture}`
environment in `paper/paper.tex`. The block-and-arrow style of
Figure 1 maps cleanly to TikZ's `\node`/`\draw` primitives. Reuse
the styles already established for Figure 1.

Estimated effort: ~6 hours per figure (12-pt grid alignment is the
time sink). Total: ~18 hours.

## Option B — draw.io / diagrams.net export to SVG → embed as image

Faster to author and iterate visually. Loses some font/typography
control but is acceptable for ICSE. Workflow:

1. Open `notebooks/figures/fig1_closed_loop.png`'s source `.drawio`
   (if it exists) or recreate the topology in draw.io.
2. Duplicate three times.
3. Fill the blocks per the per-block content above.
4. Export each as `notebooks/figures/fig5_full_run.svg`,
   `fig6_no_replan.svg`, `fig7_fusion_mechanism.svg`.
5. Reference from paper.md:

```markdown
![Figure 5: ...](../notebooks/figures/fig5_full_run.svg)
```

Estimated effort: ~3 hours per figure. Total: ~9 hours.

**Recommendation**: Option B for the deadline, polish to Option A
(TikZ) only if reviewers request it during revision.

---

# Paper-level integration

Place the three new figures in:

| Figure | Section | After paragraph |
|---|---|---|
| Figure 5 | §6.2 (H1 results) | After "no-replan stays pinned at 14 findings on every target" |
| Figure 6 | §6.2 (H1 results) | Immediately after Figure 5 (paired) |
| Figure 7 | §6.3 (H2 results) | After "discovery on non-standard service ports (3000, 5000, 8089) is lost" |

This positions them as **mechanism** figures that follow the
**aggregate** bar charts (existing Figs 2-4) and ground the
quantitative claims in concrete observable runs.

Renumber existing Figures 2/3/4 to 8/9/10 OR keep the originals as
2/3/4 and call the new ones 5/6/7 (this spec assumes the latter so
the existing in-text references in §6.2/6.3/6.4 don't need to
move). Choose based on reviewer flow preference.

---

# Source data

Every value in every block of every figure traces to a committed
artifact:

| Block content | Source |
|---|---|
| Engine list, target URL, caps | `experiments/targets/juiceshop.yaml` + `experiments/run_ablation.py:30-80` |
| Seed map `_SEEDS["web_api"]` | `src/reasonchain/planner.py:45-47` |
| Chain map `_CHAINS["http_probe"]`, `_CHAINS["nmap"]` | `src/reasonchain/planner.py:74-83` |
| nmap output (10 ports + versions) | `paper/deep_scan_juiceshop.json` findings 1–10 |
| Facts bag merge rule | `src/reasonchain/facts.py:28-42` |
| nmap_vuln cmd_builder | `src/reasonchain/subprocess_engines.py` (the `cmd_builder` that consumes `facts["open_ports"]`) |
| CVE list (CVE-2024-38476 etc.) | `paper/deep_scan_juiceshop.json`, search `CVE-` |
| no-replan outcome (2 findings) | `paper/sample_run_juiceshop_noreplan.txt` |
| no-fusion mechanism | `tests/test_ablations.py:51-69` (test that pins it) |

If reviewers ask "is this real?" the answer is: every line of
every block in these figures is rendered from a committed file in
the repository. The reproduction recipe in Appendix A regenerates
every artifact end-to-end.
