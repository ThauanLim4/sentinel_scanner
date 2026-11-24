"""Tarefa de coleta e correlação de conexões de rede."""
from __future__ import annotations

from .base import check_cancelled


def make_network_task(analyzer):
    def task(worker):
        worker.set_status("Coletando conexões…")
        connections = analyzer.snapshot()
        check_cancelled(worker)
        worker.set_status("Correlacionando indicadores…")
        findings = analyzer.analyze(connections)
        check_cancelled(worker)
        return connections, findings
    return task
