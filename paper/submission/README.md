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
