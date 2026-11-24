"""Tarefas de limpeza segura (estimativa, pré-visualização e execução)."""
from __future__ import annotations

from core import cleanup

from .base import check_cancelled


def make_estimate_task(categories):
    def task(worker):
        estimates = {}
        for category in categories:
            check_cancelled(worker)
            worker.set_status(f"Analisando {category.name}…")
            try:
                size, count = cleanup.estimate(category)
                estimates[category.key] = {"size": size, "count": count, "error": ""}
            except Exception as exc:
                estimates[category.key] = {"size": 0, "count": 0, "error": str(exc)}
        worker.set_status("Estimativas concluídas.")
        return estimates
    return task


def make_list_task(categories, limit: int = 500):
    def task(worker):
        files = []
        truncated = False
        for category in categories:
            check_cancelled(worker)
            worker.set_status(f"Listando {category.name}…")
            try:
                found = cleanup.list_files(category, limit=limit)
            except Exception:
                continue
            for item in found:
                item["category"] = category.name
                files.append(item)
            if len(found) >= limit:
                truncated = True
            if len(files) >= limit:
                files = files[:limit]
                truncated = True
                break
        return {"files": files, "truncated": truncated}
    return task


def make_clean_task(categories, db):
    def task(worker):
        results = []
        for category in categories:
            if worker.is_cancelled():
                break
            worker.set_status(f"Limpando {category.name}…")
            result = cleanup.clean(
                category,
                db=db,
                cancel=worker.is_cancelled,
                progress=lambda path: worker.set_status(f"Removendo: {path}"),
                confirmed=True,
            )
            results.append((category.key, result))
        return {"results": results, "cancelled": worker.is_cancelled()}
    return task
