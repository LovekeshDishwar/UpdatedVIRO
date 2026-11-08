# VIRO 8.2 — Multi-Format Static Detection

This release adds a dedicated static script analyser while preserving the VIRO
6.1 dashboard construction and existing PE/ML workflow.

## Newly supported script types
- Windows Batch: `.bat`, `.cmd`
- PowerShell: `.ps1`
- VBScript: `.vbs`
- JScript: `.js`

The analyser reads script text only. It does not run, invoke, interpret or execute
the submitted script. It checks configured indicators for encoded commands,
download-and-execute chains, obfuscation, persistence, destructive commands,
security-control tampering, suspicious Windows utilities, credential access and
remote-shell patterns.

A rule-based script score is an evidence score, not a calibrated malware
probability. Low-risk means no configured indicators were found, not that the
script is proven safe. Warning/high-risk results show evidence for user review.

## Safer verdict handling
- Unsupported file extensions are marked NEEDS REVIEW, not SAFE.
- Files named `.exe`, `.dll`, `.scr`, `.com` or `.pif` without an MZ header are
  marked NEEDS REVIEW and are not sent to the ML model as safe.
- Script files are never auto-organised or automatically executed.
- Suspicious/high-risk files remain user-controlled (quarantine, delete, deep
  analysis or keep).
- Existing GUI layout and dashboard construction are preserved.

## Setup (Windows)
1. Extract the ZIP.
2. Install Python 3.10+ and enable **Add Python to PATH**.
3. Double-click `install_and_run.bat`.
4. Wait for dependencies to install and VIRO to open.

Manual:
```bat
py -3 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python viro_app.py
```

## Notes and limitations
VIRO is an educational static-analysis prototype, not a replacement for antivirus.
Script pattern matching can produce false positives and false negatives. It does
not emulate scripts, inspect runtime behaviour, unpack complex obfuscation or
guarantee detection. A benign result is not proof of safety.

The existing ML model is not automatically trained on script-specific labels.
Script detection is a separate rule-based analysis path. To claim measured
accuracy, build a labelled script dataset, reserve an independent test set, and
report precision, recall, F1 and confusion matrix.

Do not execute malware samples. Use an isolated, disposable VM for controlled
research. Quarantine is a file move and metadata record, not cryptographic
isolation.


## VIRO 8.2 — Batch control-flow analysis
- Statically parses BAT/CMD labels and backward GOTO jumps.
- Highlights mkdir/md combined with cd/chdir/pushd inside a loop as potential repeated nested-directory growth.
- A single mkdir without a backward GOTO is contextual information, not a malware verdict.
- Scripts are inspected as text only and are never executed by VIRO.


## VIRO 8.2 — No fixed file-size rejection
- Removed the fixed 100 MB rejection from normal scans and deep EXE analysis.
- Large files use bounded/streaming reads where possible; PE parsing uses the file path instead of loading the entire executable into one bytes object.
- The GUI reports no fixed file-size limit.
- Script text analysis remains bounded by its configured text window for memory safety; scan details indicate when script content is truncated.
- No file is executed. Very large scans can take longer and use more CPU and disk I/O.
