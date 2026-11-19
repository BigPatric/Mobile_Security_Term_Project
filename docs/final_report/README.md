# Final Report (LaTeX)

IEEE conference format (`IEEEtran`), two columns.

| File | Contents |
|---|---|
| `main.tex` | The report |
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

`main.tex` already has one slot: save a terminal screenshot of the DOS-02 live run
as `figures/dos02_demo.png` and it replaces the placeholder box.

## Before submitting

- Set `\authorname` near the top of `main.tex`.
- Numbers come from `docs/evaluation/*.md`; if you rerun the live matrix, update
  Tables II–III and the bar chart (`\addplot` coordinates) together.
