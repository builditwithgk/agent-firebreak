#!/usr/bin/env bash
# Assemble the static Space into a folder: bash space/build.sh [OUT_DIR]   (default: space/_site)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-space/_site}"
mkdir -p "$OUT"
python - "$OUT" <<'PY'
import pathlib, shutil, sys, zipfile
out = pathlib.Path(sys.argv[1]); root = pathlib.Path("src")
with zipfile.ZipFile(out / "agent_firebreak.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for p in sorted((root / "agent_firebreak").rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts and p.suffix in {".py", ".json"}:
            z.write(p, p.relative_to(root).as_posix())
shutil.copy("space/index.html", out / "index.html")
shutil.copy("space/SPACE_README.md", out / "README.md")
PY
echo "built $OUT"
