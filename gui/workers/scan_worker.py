"""Tarefa de varredura executada em thread própria."""
from __future__ import annotations


def make_scan_task(scanner, kind: str, paths: list | None, exclude_paths: list | None):
    def task(worker):
        worker.on_cancel = scanner.cancel
        if worker.is_cancelled():
            scanner.cancel()
        return scanner.run(kind, paths, progress=worker.emit_progress,
                           exclude_paths=exclude_paths)
    return task
