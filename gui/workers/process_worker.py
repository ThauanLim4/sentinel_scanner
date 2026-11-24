"""Tarefas de análise e encerramento de processos."""
from __future__ import annotations

from .base import check_cancelled


def make_snapshot_task(analyzer, deep: bool = False, signatures: str = "none",
                       cpu_interval: float = 0.4):
    """Lê os processos ativos.

    O modo rápido (padrão) não abre os binários nem consulta assinaturas, o que
    mantém a atualização frequente da tela responsiva. A análise profunda é
    opcional e explicitamente solicitada pelo usuário.
    """
    def task(worker):
        worker.set_status("Lendo processos ativos…")
        infos = analyzer.snapshot(cpu_interval=cpu_interval, deep=deep, signatures=signatures)
        check_cancelled(worker)
        return infos
    return task


def make_count_task(analyzer):
    """Contagem rápida usada pelo dashboard; não analisa assinaturas nem conexões."""
    def task(worker):
        worker.set_status("Contando processos ativos…")
        infos = analyzer.snapshot(cpu_interval=0.0, deep=False, signatures="none")
        check_cancelled(worker)
        return len(infos)
    return task


def make_terminate_task(analyzer, info):
    def task(worker):
        worker.set_status(f"Encerrando {info.name} (PID {info.pid})…")
        return analyzer.terminate(info.pid, info.create_time, confirmed=True)
    return task
