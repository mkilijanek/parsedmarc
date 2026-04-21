from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

from app.openapi_spec import render_openapi_yaml


OUTPUT_PATH = Path("app/static/openapi-v1.yaml")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the shipped OpenAPI 3.1 artifact.")
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in artifact is out of date.")
    args = parser.parse_args()

    generated = render_openapi_yaml()
    current = OUTPUT_PATH.read_text(encoding="utf-8") if OUTPUT_PATH.exists() else ""

    if args.check:
        if current != generated:
            diff = "".join(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    generated.splitlines(keepends=True),
                    fromfile=str(OUTPUT_PATH),
                    tofile="generated-openapi-v1.yaml",
                )
            )
            sys.stderr.write("OpenAPI artifact drift detected. Re-run scripts/generate_openapi.py.\n")
            sys.stderr.write(diff)
            return 1
        print(f"{OUTPUT_PATH} is up to date")
        return 0

    OUTPUT_PATH.write_text(generated, encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
