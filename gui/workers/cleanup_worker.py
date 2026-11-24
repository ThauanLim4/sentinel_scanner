"""Tarefas de limpeza segura (estimativa, pré-visualização e execução).

A execução exige ``confirmed=True`` na fábrica, fornecido somente depois de a
tela apresentar a prévia e obter confirmação explícita. A seleção individual
usada pela prévia é repassada ao núcleo como filtro aditivo; todas as regras de
segurança continuam em ``core/cleanup.py``.
"""
from __future__ import annotations

import os

from core import cleanup

from .base import check_cancelled


class ConfirmationRequired(RuntimeError):
    """A tela tentou executar a limpeza sem confirmação."""


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
    """Prévia somente leitura; falhas por categoria são devolvidas, não ocultas."""

    def task(worker):
        files = []
        errors = {}
        truncated = False
        for category in categories:
            if category.kind == "recycle":
                continue  # a Lixeira não oferece prévia individual pela API do núcleo
            check_cancelled(worker)
            worker.set_status(f"Listando {category.name}…")
            try:
                found = cleanup.list_files(category, limit=limit)
            except Exception as exc:
                errors[category.key] = str(exc)
                continue
            for item in found:
                item["category"] = category.name
                item["category_key"] = category.key
                try:
                    item["mtime"] = os.path.getmtime(item["path"])
                except OSError:
                    item["mtime"] = None
                files.append(item)
            if len(found) >= limit:
                truncated = True
            if len(files) >= limit:
                files = files[:limit]
                truncated = True
                break
        return {"files": files, "truncated": truncated, "errors": errors}
    return task


def make_analysis_task(categories, limit: int = 500):
    """Estimativa + prévia em uma única thread, com erros parciais explícitos."""

    estimate_task = make_estimate_task(categories)
    list_task = make_list_task(categories, limit=limit)

    def task(worker):
        estimates = estimate_task(worker)
        preview = list_task(worker)
        return {"estimates": estimates, "preview": preview}

    return task


def make_clean_task(categories, db, *, confirmed: bool = False,
                    only_paths: dict | None = None, include_recycle: bool = False):
    if not confirmed:
        raise ConfirmationRequired("A limpeza exige confirmação explícita da tela.")

    selected_categories = [c for c in categories
                           if c.kind != "recycle" or include_recycle]

    def task(worker):
        results = []
        for category in selected_categories:
            if worker.is_cancelled():
                break
            worker.set_status(f"Limpando {category.name}…")
            paths = None if category.kind == "recycle" else \
                (only_paths or {}).get(category.key)
            result = cleanup.clean(
                category,
                db=db,
                cancel=worker.is_cancelled,
                progress=lambda path: worker.set_status(f"Removendo: {path}"),
                confirmed=True,
                only_paths=paths,
            )
            results.append({"key": category.key, "name": category.name,
                            "freed": result.freed, "deleted": result.deleted,
                            "skipped": result.skipped, "errors": list(result.errors)})
        return {"results": results, "cancelled": worker.is_cancelled()}
    return task
