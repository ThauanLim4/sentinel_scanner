"""Tarefa de consulta do estado do Windows Defender (nunca altera configurações)."""
from __future__ import annotations


def make_defender_status_task(client):
    def task(worker):
        worker.set_status("Consultando o Windows Defender…")
        return client.status()
    return task
