"""
Deduplicator — removes near-duplicate findings before reporting.

Deduplication key = (type, hostname, title)
Keeps the highest-confidence duplicate.
"""

from __future__ import annotations
from typing import List, Dict


CONF_RANK = {"high": 3, "medium": 2, "low": 1}


class Deduplicator:
    def deduplicate(self, findings: List[Dict]) -> List[Dict]:
        best: Dict[str, Dict] = {}

        for f in findings:
            key = (
                f.get("type", ""),
                f.get("hostname", f.get("url", "")),
                f.get("title", ""),
            )
            key_str = "|".join(str(k) for k in key)

            if key_str not in best:
                best[key_str] = f
            else:
                # Keep the one with higher confidence
                existing_conf = CONF_RANK.get(best[key_str].get("confidence", "low"), 1)
                new_conf      = CONF_RANK.get(f.get("confidence", "low"), 1)
                if new_conf > existing_conf:
                    best[key_str] = f

        return list(best.values())
