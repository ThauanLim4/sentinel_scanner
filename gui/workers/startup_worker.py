"""Tarefas de análise e alteração de entradas de inicialização.

A análise é somente leitura. Desativar/reativar sempre executa no núcleo
(`StartupManager`), que valida confirmação, itens críticos e drivers.
"""
from __future__ import annotations

from .base import check_cancelled


def make_startup_task(analyzer, deep: bool = True):
    def task(worker):
        worker.set_status("Coletando entradas de inicialização…")
        entries = analyzer.analyze(deep=deep)
        # O núcleo não oferece cancelamento interno; se o usuário cancelar durante
        # a coleta, o resultado é descartado ao final, sem alterar nada.
        check_cancelled(worker)
        return entries
    return task


def make_startup_disable_task(manager, entry, confirm_critical: bool = False):
    def task(worker):
        worker.set_status(f"Desativando {entry.name}…")
        check_cancelled(worker)
        return manager.disable(entry, confirmed=True, confirm_critical=confirm_critical)
    return task


def make_startup_enable_task(manager, entry, confirm_critical: bool = False):
    def task(worker):
        worker.set_status(f"Reativando {entry.name}…")
        check_cancelled(worker)
        return manager.enable(entry, confirmed=True, confirm_critical=confirm_critical)
    return task
