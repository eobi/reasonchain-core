# Research Closeout — ReasonChain / SRF Paper

Owner: Obi Ebuka David · Advisor: Dr. Sayed Erfan Arefin
University of Dayton, Summer Research Fellowship 2026

This file tracks every remaining task to take the ReasonChain
research from where it is now (working artifact + draft paper) to
a state that supports (a) SRF deliverable submission, (b) USENIX
WOOT / ACM CODASPY submission, and (c) AFRL outreach for
follow-on funding.

Time horizons are realistic, not aspirational. Owners are
explicit. Checkmarks mean *materially complete*, not *touched*.

---

## Phase 0 — Final automated pipeline (tonight → tomorrow morning)

Status: **in flight** (LLM sweep running in background; downstream
steps are scripted and will run when sweep completes).

- [ ] **0.1** LLM-planner sweep on 5 representative targets
      (juiceshop, bwapp, commix_testbed, pygoat, skf_xss) ·
      `scripts/run_llm_sweep.py` · ETA ~60 min
- [ ] **0.2** `scripts/fill_paper.py` substitutes real numbers
      into `paper/paper.md` → `paper/paper_filled.md`
- [ ] **0.3** Re-execute `notebooks/h1_h2_h3_analysis.ipynb`
      to refresh H1/H2/H3 PNG figures with the 68-cell results
- [ ] **0.4** Re-render `paper/paper.pdf` with the filled
      numbers via `scripts/render_paper.py`
- [ ] **0.5** Re-render `reports/matrix_report.pdf` from the
      finished `data/results.csv`
- [ ] **0.6** Deep Juice Shop live scan (10-engine Kali pool)
      → `reports/juiceshop_deep.{pdf,json}` so the live CVE
      artifact references the latest engine config
- [ ] **0.7** Final commit + push to
      <https://github.com/eobi/reasonchain-core>

**Definition of done for Phase 0:** Paper PDF, matrix report PDF,
deep-scan PDF, refreshed figures, and CSV all reflect the final
68-cell matrix data. GitHub `main` is up to date.

---

## Phase 1 — Paper polish (next 24–48 hours)

Status: pending Phase 0.

- [ ] **1.1** Read `paper/paper.pdf` end-to-end (~1–2 hr).
      Flag every rough sentence, unclear figure caption, and
      any number that doesn't match the CSV.
- [ ] **1.2** Add **head-to-head vs PentestGPT** on Juice Shop.
      Document procedure, run both, compare findings counts and
      coverage. Adds ~half a page to results and a strong
      reviewer hook.
- [ ] **1.3** Tighten **§2 Related Work**. Cite AIxCC explicitly,
      cite MetaGPT and AutoGPT-cyber, position ReasonChain as
      complementary to CRSes (binary-focused) vs. ReasonChain
      (web-focused).
- [ ] **1.4** Add **Figure 1: the closed loop**. ASCII or proper
      PNG via mermaid. Place at the top of §3.
- [ ] **1.5** Update README to feature `paper/paper.pdf`
      prominently above the architecture section.
- [ ] **1.6** Send draft + matrix report to **Dr. Arefin** with a
      short note asking for review on §6 (results) + §8
      (limitations).

**Definition of done for Phase 1:** Paper reads cleanly end-to-
end. Every figure has a caption that explains what it shows and
why. Dr. Arefin has seen v1 of the draft.

---

## Phase 2 — Submission + outreach (next week)

Status: pending Phase 1.

### 2A. Paper submission
- [ ] **2.1** Pick venue. **Recommended: USENIX WOOT
      workshop** (best fit for "we built and evaluated an
      autonomous pentest agent"). Backup: ACM CODASPY,
      IEEE S&P AI Workshop.
- [ ] **2.2** Reformat `paper/paper.md` → USENIX LaTeX template.
      ~2–3 hr. (Markdown → pandoc → tex → manual cleanup.)
- [ ] **2.3** Address Dr. Arefin's review comments.
- [ ] **2.4** Submit. (1 hr; HotCRP or similar.)
- [ ] **2.5** Archive submission PDF + supplementary materials
      in `paper/submission/`.

### 2B. IP clarity for Pentagon (CRITICAL — do before AFRL outreach)
- [ ] **2.6** Email **UD Office of Technology Commercialization**
      (OTC). Ask for a 30-min meeting to clarify Pentagon's IP
      lineage. Three scenarios to disambiguate:
       - A. Pentagon is yours personally (built on personal
            equipment, personal time).
       - B. Pentagon is UD's (substantially developed during
            SRF on UD systems).
       - C. Mixed — license path via UD OTC.
- [ ] **2.7** Get the answer **in writing** before pitching
      Pentagon to AFRL. This is the single biggest landmine.
- [ ] **2.8** If Path A or B, plan SBIR-vehicle small business
      formation. If C, plan UD OTC license terms.

### 2C. AFRL outreach
- [ ] **2.9** Draft **1-page brief** for AFRL: what
      ReasonChain is, what it shows (3 hypotheses + real
      CVEs), and the proposed Phase I scope (1 hr).
- [ ] **2.10** Dr. Arefin sends the intro email to **AFRL/RIGA
      cyber AI lead** (Rome, NY). CC the OTC contact for
      visibility. (15 min for Dr. Arefin.)
- [ ] **2.11** Prepare a 30-min screenshare demo: live ablation
      run + the matrix report PDF + the deep-scan PDF. Pre-
      record a 5-min Loom video as backup.

**Definition of done for Phase 2:** Paper submitted to a peer-
reviewed venue. UD OTC has confirmed Pentagon's IP path in
writing. AFRL has received the intro email.

---

## Phase 3 — Research extensions (next month, for camera-ready / Chapter 4)

Status: pending Phase 2.

- [ ] **3.1** Recruit **3 human experts** (DCE faculty, PhD
      students, or local cyber community). Record baselines for
      3 representative targets via:
      ```
      python -m reasonchain.human_baseline \
          --target juiceshop --expert-id E01 --findings N \
          --high N --medium N --duration-minutes T \
          --tools "burp,sqlmap,nmap" --notes "..."
      ```
      (~4–6 hr of coordination total.)
- [ ] **3.2** Add **exploitation phase**. Three new engines:
      sqlmap (real fire, not detection-only), dalfox (live XSS
      payload firing on a flag), metasploit-rpc (controlled).
      Architectural change: add a `phase=exploit` to
      Orchestrator after detection. (~1 week.)
- [ ] **3.3** Add **network target class** (CIDR / IP target_type).
      Adds nmap-leading seed set. Reuses every existing engine.
      (~3–5 days.)
- [ ] **3.4** Scale to **30+ targets**. Add HTB Starting Point
      retired machines, VulnHub Kioptrix / Mr-Robot / DC-1
      series, NodeGoat, Hackazon. (~1 week.)
- [ ] **3.5** **Multi-model LLM planner comparison** (Claude
      Sonnet, Claude Opus, GPT-4o, Llama-3-70B via Together).
      Adds the LLM-vs-LLM-vs-heuristic figure for H3. (~2 days,
      ~$10 in API.)

**Definition of done for Phase 3:** Paper has human-baseline
evidence, end-to-end exploitation evidence, network-class
evidence, and 30+ targets. Camera-ready quality.

---

## Phase 4 — Thesis chapters (parallel to Phase 2/3)

Status: pending Phase 0.

- [ ] **4.1** Outline thesis chapters 1–6 per the SRF proposal:
       - Ch. 1: Introduction
       - Ch. 2: Background + Related Work
       - Ch. 3: ReasonChain Architecture (design contribution)
       - Ch. 4: Empirical Study (H1 / H2 / H3, SRF paper)
       - Ch. 5: Multi-domain Fusion (network + web + database)
       - Ch. 6: LLM Reasoning Analysis (when to trust autonomy)
       - Ch. 7: Conclusions, Future Directions, Journal Paper
- [ ] **4.2** Map SRF paper → Chapter 4 verbatim (with
      figures + matrix report as appendices).
- [ ] **4.3** Draft Chapter 5 plan (multi-domain). Network
      class lands here.
- [ ] **4.4** Schedule **thesis committee meeting** for September
      2026 (after paper submission, before fall semester).
- [ ] **4.5** Identify external committee member (ideally
      AFRL-affiliated if the AFRL outreach has landed).

**Definition of done for Phase 4:** Thesis outline approved by
committee. Chapter 4 draft is the SRF paper. Chapters 5 + 6
have concrete experiment plans.

---

## Shippable checkpoints (you can stop at any of these)

| Milestone | What's in it | Time-to-reach from now |
|---|---|---|
| **A. Phase 0 done** | Paper PDF, matrix report PDF, deep-scan PDF, GitHub up to date. Defensible as "preliminary results draft." | tomorrow morning |
| **B. Phase 1 done** | Paper polished, reviewed by Dr. Arefin, ready to submit. | end of week |
| **C. Phase 2 done** | Submitted to USENIX WOOT. UD OTC has signed off. AFRL has been contacted. SRF deliverable complete. | end of next week |
| **D. Phase 3 done** | Human baselines + exploitation + network + 30+ targets. Camera-ready. | end of summer |
| **E. Phase 4 done** | Thesis chapters mapped and committee-approved. | September 2026 |

**Operator recommendation:** stop at **Milestone C** for the SRF
deliverable. Run Phase 3 + 4 in parallel through Fall 2026 as
thesis depth without blocking submission.

---

## Reference — key files & commands

- Paper draft: [`paper/paper.md`](paper/paper.md)
- Paper PDF: [`paper/paper.pdf`](paper/paper.pdf)
- Matrix data: [`data/results.csv`](data/results.csv) · summary
  [`data/summary.csv`](data/summary.csv)
- Analysis notebook: [`notebooks/h1_h2_h3_analysis.ipynb`](notebooks/h1_h2_h3_analysis.ipynb)
- Figures: [`notebooks/figures/`](notebooks/figures/)
- Per-run reports: [`reports/`](reports/)
- Live deep scan: [`reports/juiceshop_deep.pdf`](reports/juiceshop_deep.pdf)
- Matrix summary report: [`reports/matrix_report.pdf`](reports/matrix_report.pdf)

```bash
# Fill paper with real numbers (after matrix completes)
python scripts/fill_paper.py
# Re-render figures
jupyter nbconvert --to notebook --execute \
    notebooks/h1_h2_h3_analysis.ipynb \
    --output notebooks/h1_h2_h3_analysis.ipynb
# Re-render paper PDF
python scripts/render_paper.py
# Re-render matrix summary PDF
python scripts/render_matrix_report.py
# Run a fresh deep scan on Juice Shop
python scripts/render_deep_scan.py \
    --target http://192.168.1.73:3000/ --name juiceshop_deep
```
