"""Produce bounded UTF-8 JSON and Markdown using only the standard library."""
import csv
import json
from collections import defaultdict
from pathlib import Path

amounts = defaultdict(int)
with Path("data.csv").open(encoding="utf-8", newline="") as source:
    for row in csv.DictReader(source):
        amounts[row["category"]] += int(row["amount"])
Path("report.json").write_text(json.dumps(dict(sorted(amounts.items())), indent=2) + "\n", encoding="utf-8")
Path("report.md").write_text("# Report\n\n" + "\n".join(f"- {name}: {amount}" for name, amount in sorted(amounts.items())) + "\n", encoding="utf-8")
