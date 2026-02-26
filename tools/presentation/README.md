# Presentation Builder

This folder contains an isolated script for generating the classroom demo deck from `Demo.md`.

## Install

```bash
python -m venv tools/presentation/.venv
tools/presentation/.venv/bin/python -m pip install -r tools/presentation/requirements.txt
```

## Build

```bash
tools/presentation/.venv/bin/python tools/presentation/build_demo_ppt.py \
  --source Demo.md \
  --out artifacts/NIDS_Demo_Modern.pptx
```

## Notes

- Output format is editable `.pptx` (16:9).
- The script extracts the full live demo block from section 6 in `Demo.md` for the appendix slide.
- Speaker notes are added to all slides.
