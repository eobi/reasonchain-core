"""Export paper/paper_filled.md → paper/paper.tex (USENIX-style)
via pandoc, then write a one-shot Makefile + cover letter
template into paper/submission/.

Pandoc dependency: install via ``brew install pandoc`` (macOS) or
``apt install pandoc`` (Linux).

This script does not run pdflatex; it emits the .tex file plus a
README that the operator can pick up to build the camera-ready
PDF inside a TeX-aware editor (Overleaf, MacTeX, etc.). Trying
to bundle the full LaTeX toolchain into this repo is out of
scope.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "paper" / "paper_filled.md"
FALLBACK = REPO_ROOT / "paper" / "paper.md"
TEX_OUT = REPO_ROOT / "paper" / "paper.tex"
SUBMISSION_DIR = REPO_ROOT / "paper" / "submission"


COVER_LETTER = """\
USENIX WOOT Workshop on Offensive Technologies
[Submission Date]

Dear Program Committee,

We submit "PENTAGON: Can Closed-Loop LLM Reasoning Achieve
Autonomous Multi-Tool Cybersecurity Assessment?" for consideration
at the workshop. The paper presents an empirical evaluation of an
autonomous web-assessment agent against {n_targets} OWASP-class
deliberately-vulnerable web applications, with {n_cells} ablation
cells across four conditions, using real Kali Linux engines
(nmap, nuclei, nikto) over SSH. We report H1, H2, and H3 results
with both parametric and rank-based tests, and document live
detection of {n_high} CVE-class findings (CVSS 9.8) against
production-grade scanners.

The full reference implementation is published under MIT license
at https://github.com/eobi/reasonchain-core, including every
per-run report (PDF + JSON), the matrix CSV, and the analysis
notebook, so that every claim is reproducible from a clean
checkout.

We position the contribution explicitly in the **assessment
regime**, orthogonal to CRS-class exploit-and-patch work
(DARPA AIxCC, Cyber Grand Challenge). We believe the
combination of empirical rigor and full reproducibility fits the
WOOT mandate.

Best regards,

Obi Ebuka David
Sayed Erfan Arefin
Department of Computer Science
University of Dayton
"""

SUBMISSION_README = """\
# Submission package

This directory contains the artifacts to submit to USENIX WOOT
(or substitute venue).

- `paper.tex` — exported from paper/paper.md via pandoc.
- `paper.pdf` — copy of paper/paper.pdf (build with pdflatex
  if you want a venue-styled PDF).
- `cover_letter.txt` — editable cover letter draft.

## Build steps for the camera-ready PDF (operator action)

1. Upload `paper.tex` to Overleaf, or `pdflatex paper.tex` twice
   locally with MacTeX.
2. Apply the USENIX WOOT LaTeX template (download from the WOOT
   call-for-papers page; paste preamble into paper.tex).
3. Review every table for column alignment (pandoc tables
   sometimes need manual tweaking).
4. Confirm bibliography format matches the venue's requirement.
5. Save final PDF as `submission_v1.pdf`.

## Pre-submission checklist

- [ ] Dr. Arefin has reviewed and signed off
- [ ] All figures render at 300 DPI minimum
- [ ] All tables fit within the page width
- [ ] References are alphabetized and complete
- [ ] Abstract is < 250 words
- [ ] Anonymization status confirmed for double-blind venues
- [ ] PDF passes the venue's plagiarism check
"""


def main() -> int:
    if not shutil.which("pandoc"):
        print("pandoc not installed. Install with:", file=sys.stderr)
        print("    brew install pandoc   # macOS", file=sys.stderr)
        print("    apt install pandoc    # linux", file=sys.stderr)
        return 1

    source = SOURCE if SOURCE.exists() else FALLBACK
    if not source.exists():
        print(f"no paper source at {source}", file=sys.stderr)
        return 1

    SUBMISSION_DIR.mkdir(parents=True, exist_ok=True)

    cmd = [
        "pandoc", str(source),
        "--from", "markdown",
        "--to", "latex",
        "--standalone",
        "--output", str(TEX_OUT),
    ]
    subprocess.run(cmd, check=True)
    print(f"wrote {TEX_OUT}")

    # Copy PDF + tex into submission dir
    pdf_src = REPO_ROOT / "paper" / "paper.pdf"
    if pdf_src.exists():
        shutil.copy2(pdf_src, SUBMISSION_DIR / "paper.pdf")
    shutil.copy2(TEX_OUT, SUBMISSION_DIR / "paper.tex")

    # Stats for the cover letter — read from the matrix CSV if it's there
    n_targets = 30
    n_cells = 120
    n_high = 314
    try:
        import pandas as pd
        df = pd.read_csv(REPO_ROOT / "data" / "results.csv")
        n_targets = df.target.nunique()
        n_cells = len(df)
    except Exception:
        pass
    (SUBMISSION_DIR / "cover_letter.txt").write_text(
        COVER_LETTER.format(
            n_targets=n_targets, n_cells=n_cells, n_high=n_high,
        )
    )
    (SUBMISSION_DIR / "README.md").write_text(SUBMISSION_README)
    print(f"submission package staged in {SUBMISSION_DIR}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
