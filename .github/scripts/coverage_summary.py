"""Writes gcovr's JSON summary as a Markdown table, most uncovered lines first."""
import json
import sys

summary = json.load(open(sys.argv[1]))


def cell(covered, total):
    percent = 100.0 * covered / total if total else 100.0
    return f"{percent:.1f}% ({covered} / {total})"


print("| File | Lines | Branches |")
print("|---|---|---|")
files = sorted(summary["files"],
               key=lambda f: f["line_total"] - f["line_covered"], reverse=True)
for f in files:
    print(f"| `{f['filename']}` | {cell(f['line_covered'], f['line_total'])} "
          f"| {cell(f['branch_covered'], f['branch_total'])} |")
print(f"| **Total** | **{cell(summary['line_covered'], summary['line_total'])}** "
      f"| **{cell(summary['branch_covered'], summary['branch_total'])}** |")
