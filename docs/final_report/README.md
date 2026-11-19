# Final Report (LaTeX)

IEEE conference format (`IEEEtran`), two columns.

| File | Contents |
|---|---|
| `main.tex` | The report (LaTeX, matches `final_report_v2.docx`) |
| `final_report_v2.docx` | Word version of the report |
| `final_report.docx` | Earlier Word draft |
| `references.bib` | Bibliography (BibTeX) |
| `figures/` | Images included with `\includegraphics` (PNG, JPG or PDF) |

## Build

**Overleaf:** upload this folder (or zip it) and compile with pdfLaTeX.

**Locally:** install a TeX distribution (`brew install --cask mactex-no-gui`, or `brew install tectonic`), then:

```bash
latexmk -pdf main.tex      # or: tectonic main.tex
```

## Figures

The architecture diagram, the FSM and both charts are drawn in TikZ/pgfplots inside
`main.tex`, so they need no image files and their numbers can be edited in place.

To add a picture, put it in `figures/` and reference it by file name:

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\columnwidth]{my_screenshot.png}
  \caption{...}
  \label{fig:my-screenshot}
\end{figure}
```

Use `figure*` with `width=\textwidth` for a figure that spans both columns.

Screenshots in `figures/` come from the live runs in the progress report:

| File | Used by | Content |
|---|---|---|
| `tex_smf_release_log.png` | LaTeX | free5GC SMF log of one release (ground truth) |
| `tex_enum_off.png`, `tex_enum_on.png` | LaTeX | ENUM-01 without / with L1 (cropped to calls + verdict) |
| `tex_dos02_l1l2.png`, `tex_dos02_full.png` | LaTeX | DOS-02 under L1+L2 vs the full gateway |
| `fig_*.png` | Word | Same content, merged into single images; plus the four charts/diagrams |

## Before submitting

- Numbers come from `docs/evaluation/*.md`; if you rerun the live matrix, update
  Tables II–III and the bar chart (`\addplot` coordinates) together.
