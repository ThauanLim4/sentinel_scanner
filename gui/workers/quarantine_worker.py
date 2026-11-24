"""Tarefas de quarentena chamadas pela interface (sempre com confirmação explícita)."""
from __future__ import annotations

from pathlib import Path

from .base import check_cancelled


def make_quarantine_task(quarantine, path: str, evidences: list | None = None,
                         allowed_roots: list | None = None):
    def task(worker):
        worker.set_status(f"Isolando {Path(path).name}…")
        check_cancelled(worker)
        return quarantine.quarantine_file(
            path,
            evidences=evidences or [],
            allowed_roots=allowed_roots or [str(Path(path).anchor or "/")],
            confirmed=True,
        )
    return task
