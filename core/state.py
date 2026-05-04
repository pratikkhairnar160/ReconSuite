"""
StateManager — persists pipeline state to disk for checkpoint/resume.

Session data lives in ./sessions/<session_id>.json
"""

from __future__ import annotations
import json
import uuid
import time
from pathlib import Path
from typing import Any, Dict, Optional


SESSION_DIR = Path("./sessions")


class StateManager:
    def __init__(
        self,
        session_id: Optional[str] = None,
        resume_id: Optional[str] = None,
    ):
        SESSION_DIR.mkdir(parents=True, exist_ok=True)

        if resume_id:
            self.session_id = resume_id
            self._state = self._load(resume_id)
            self._state.setdefault("resumed", True)
        else:
            self.session_id = session_id or uuid.uuid4().hex[:12]
            self._state: Dict[str, Any] = {
                "session_id": self.session_id,
                "created_at": time.time(),
                "stages_completed": [],
                "data": {},
            }
            self._save()

    # ------------------------------------------------------------------
    # Stage-level checkpoint helpers
    # ------------------------------------------------------------------

    def stage_done(self, stage: str) -> bool:
        return stage in self._state.get("stages_completed", [])

    def mark_stage_done(self, stage: str):
        if stage not in self._state["stages_completed"]:
            self._state["stages_completed"].append(stage)
        self._save()

    # ------------------------------------------------------------------
    # Data store — each stage reads/writes its own namespace
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        return self._state["data"].get(key, default)

    def set(self, key: str, value: Any):
        self._state["data"][key] = value
        self._save()

    def update(self, key: str, items: list):
        """Extend a list in the store, deduplicating by item identity."""
        existing = self._state["data"].get(key, [])
        seen = {json.dumps(i, sort_keys=True) for i in existing}
        for item in items:
            serialised = json.dumps(item, sort_keys=True)
            if serialised not in seen:
                existing.append(item)
                seen.add(serialised)
        self._state["data"][key] = existing
        self._save()

    # ------------------------------------------------------------------
    # Internal I/O
    # ------------------------------------------------------------------

    def _path(self, sid: str) -> Path:
        return SESSION_DIR / f"{sid}.json"

    def _save(self):
        self._path(self.session_id).write_text(
            json.dumps(self._state, indent=2, default=str)
        )

    def _load(self, sid: str) -> Dict[str, Any]:
        p = self._path(sid)
        if not p.exists():
            raise FileNotFoundError(f"Session not found: {sid}  (looked in {p})")
        return json.loads(p.read_text())
