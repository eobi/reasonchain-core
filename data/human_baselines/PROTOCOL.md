# Human-Expert Baseline Recording Protocol

This protocol implements deliverable #6 of the SRF proposal
("Establish human baseline"). Three expert assessors run a
time-boxed manual web-application assessment against each of
three targets; the recorded numbers feed the head-to-head
comparison in paper §6.10.

## Targets

| Stem | Target URL | Why |
|---|---|---|
| `juiceshop` | http://localhost:3000/ | Modern Node.js SPA, broad attack surface |
| `dvwa` | http://localhost:8090/login.php | Classic LAMP teaching app |
| `bwapp` | http://localhost:8081/portal.php | Broad PHP attack surface, ~100 issues |

Each target runs in a Docker container that the assessor can
restart between sessions. Container commands are in the repo
README under §3.

## Procedure (per expert × per target)

1. **Setup (≤10 min).** Spin up the target's Docker container.
   Confirm reachability with a single browser visit. Restart the
   container if the expert is going second or third on the same
   target so the state is identical.
2. **Assessment (90 min hard cap).** The expert performs a
   black-box manual assessment with whatever tools they prefer
   (Burp Suite, sqlmap, nmap, nuclei, browser dev tools, custom
   scripts, etc.). They may consult public OWASP references but
   not finding databases keyed on the specific Docker image.
3. **Recording (≤10 min).** Immediately after the 90-minute
   timer expires, the expert records the findings via the CLI
   described below.

## Recording CLI

```bash
python -m reasonchain.human_baseline \
    --target <juiceshop|dvwa|bwapp> \
    --expert-id E0N \
    --findings <total distinct vuln count> \
    --critical <N> \
    --high <N> \
    --medium <N> \
    --low <N> \
    --info <N> \
    --duration-minutes 90 \
    --tools "burp, sqlmap, nmap, nuclei, custom-script" \
    --notes "<one-paragraph methodology summary>"
```

Each invocation writes to
`data/human_baselines/<target>/<expert_id>.yaml`. The expert may
re-run the CLI to correct numbers; the YAML is overwritten.

## What counts as a "finding"

For consistency with the autonomous runs, **one finding is one
distinct vulnerability instance** (not one CVE, not one
parameter). Examples:

- Reflected XSS in `?q=` on `/search` → 1 finding
- Reflected XSS in `?id=` on `/product` → 1 finding (distinct
  parameter location)
- Missing `Content-Security-Policy` header on the seed page →
  1 finding
- The same missing header on every page → still 1 finding
  (engine-level missing header is engine-level, not page-level)
- 4 separate CVE IDs against the same outdated Apache version
  → 4 findings (each CVE is a distinct vulnerability)
- 50 endpoints discovered by content discovery without further
  verification → 0 findings (they are reachable paths, not
  confirmed vulnerabilities)

## Expert recruitment

Need **3 distinct assessors**, identified as E01, E02, E03 in
the recorded data. To preserve double-blind integrity, recruit:

- **E01** = the paper's first author (Obi). Conducted first to
  anchor the methodology.
- **E02 and E03** = two University of Dayton classmates from
  CPS-595 (Information Assurance) or CPS-690 (Advanced
  Cybersecurity), recruited through Dr. Arefin's research group.

Each expert assesses all three targets but in different orders to
control for fatigue + learning effects:

| Expert | Order |
|---|---|
| E01 | juiceshop → dvwa → bwapp |
| E02 | dvwa → bwapp → juiceshop |
| E03 | bwapp → juiceshop → dvwa |

## Time budget for the operator (you)

- Recruit 2 assessors: ~1 hr (~30 min each)
- 3 × E01 sessions: 3 × 100 min = 5 hrs
- E02 + E03 supervision + interview: 6 hrs over 2 days
- Aggregate + paper write-up: 2 hrs

**Total: 14–15 hours over 5 calendar days.**

## Acceptance test

After all 9 baselines are recorded, this command must return 9:

```bash
python -c "from reasonchain.human_baseline import load_all_baselines; \
    print(len(load_all_baselines()))"
```

The paper renderer reads `data/human_baselines/` directly and
emits the comparison table in §6.10 automatically.
