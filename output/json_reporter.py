"""
JSONReporter — writes structured results to a JSON file.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict


class JSONReporter:
    def __init__(self, results: Dict):
        self.results = results

    def write(self, path: Path):
        path.write_text(json.dumps(self.results, indent=2, default=str))
