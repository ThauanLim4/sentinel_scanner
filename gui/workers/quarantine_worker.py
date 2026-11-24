"""Tarefas de quarentena chamadas pela interface.

Toda operação destrutiva exige ``confirmed=True`` na fábrica: a confirmação é
dada pela tela antes de iniciar a thread. A lista é somente leitura e passa
sempre pelo ``core/quarantine.py`` (nunca lê arquivos ``.qz`` diretamente).
"""
from __future__ import annotations

from pathlib import Path

from .base import check_cancelled


class ConfirmationRequired(RuntimeError):
    """A tela tentou executar uma operação destrutiva sem confirmação."""


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


def make_quarantine_list_task(quarantine, status: str | None = None):
    """Lista itens em todas as fases (``status=None``) ou filtrados pelo banco."""

    def task(worker):
        worker.set_status("Consultando itens da quarentena…")
        check_cancelled(worker)
        return quarantine.list_items(status=status)

    return task


def make_restore_task(quarantine, qid: str, destination=None, overwrite: bool = False,
                      *, confirmed: bool = False):
    if not confirmed:
        raise ConfirmationRequired("A restauração exige confirmação explícita da tela.")
    dest = str(destination) if destination else ""

    def task(worker):
        worker.set_status(f"Restaurando item {qid}…")
        check_cancelled(worker)
        return quarantine.restore(qid, destination=dest or None, overwrite=bool(overwrite))

    return task


def make_delete_task(quarantine, qid: str, *, confirmed: bool = False):
    if not confirmed:
        raise ConfirmationRequired("A exclusão definitiva exige confirmação explícita da tela.")

    def task(worker):
        worker.set_status(f"Removendo definitivamente o item {qid}…")
        check_cancelled(worker)
        quarantine.delete_permanently(qid, confirmed=True)
        return qid

    return task
