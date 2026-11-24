"""Tarefas do Microsoft Defender: consultas, definições e verificações.

Este módulo nunca desativa proteções nem altera exclusões. As únicas operações
registradas no banco são aquelas cujo resultado real foi confirmado pelo núcleo
(``update_signatures`` e ``Start-MpScan``). Consultas não são registradas.
"""
from __future__ import annotations

import time

from core.logger import get_logger

from .base import TaskCancelled, check_cancelled

log = get_logger("gui.workers.defender")

SCAN_LABELS = {"quick": "rápida", "full": "completa"}
SCAN_ACTIONS = {"quick": "defender_scan_quick", "full": "defender_scan_full"}


def make_defender_status_task(client):
    def task(worker):
        worker.set_status("Consultando o Windows Defender…")
        return client.status()
    return task


def make_defender_update_task(client, db=None):
    """Atualiza definições e registra no banco somente o retorno real do núcleo."""

    def task(worker):
        worker.set_status("Atualizando as definições do Defender…")
        check_cancelled(worker)
        ok = bool(client.update_signatures())
        log_error = _log_defender(db, "defender_update", "Microsoft Defender",
                                  "Atualização de definições", ok)
        check_cancelled(worker)
        return {"ok": ok, "log_error": log_error}

    return task


def make_defender_scan_task(client, kind: str, db=None):
    """Executa uma verificação real do Defender com progresso e cancelamento."""
    if kind not in SCAN_LABELS:
        raise ValueError("kind deve ser 'quick' ou 'full'")

    def task(worker):
        label = SCAN_LABELS[kind]
        worker.set_status(f"Iniciando verificação {label} do Defender…")
        check_cancelled(worker)
        scan = client.start_scan(kind)
        # O cancelamento da thread interrompe o processo iniciado por `start_scan`.
        # Limitação documentada: DefenderScan.cancel() também cancela uma
        # verificação global em andamento iniciada fora do Sentinel.
        worker.on_cancel = scan.cancel
        try:
            scan.start()
            while scan.running():
                check_cancelled(worker)
                worker.emit_progress({"phase": "running", "kind": kind})
                time.sleep(0.5)
            if worker.is_cancelled():
                raise TaskCancelled()
            code, output = scan.wait()
            ok = code == 0
            detail = f"código={code}"
            if output:
                detail += f": {output[:200]}"
            log_error = _log_defender(db, SCAN_ACTIONS[kind], "Microsoft Defender",
                                      detail, ok)
            return {"ok": ok, "returncode": code, "output": output[:1000],
                    "log_error": log_error}
        finally:
            worker.on_cancel = None

    return task


def make_defender_query_task(client, section: str):
    """Leituras isoladas: uma falha parcial não invalida as demais consultas."""
    if section not in ("threats", "history", "exclusions", "results"):
        raise ValueError("section inválida")

    def task(worker):
        worker.set_status("Consultando dados do Defender…")
        check_cancelled(worker)
        if section == "threats":
            data = client.threats()
        elif section == "history":
            data = client.history()
        elif section == "exclusions":
            data = client.exclusions()
        else:
            data = {"threats": client.threats(), "history": client.history()}
        check_cancelled(worker)
        return data

    return task


def _log_defender(db, action: str, target: str, detail: str, ok: bool) -> str:
    if db is None:
        return "Banco indisponível: operação não registrada no histórico."
    try:
        db.log_action(action, target, detail, ok)
        return ""
    except Exception as exc:  # a operação real já terminou; não alterar seu resultado
        log.error("Falha ao registrar %s no banco: %s", action, exc)
        return f"Operação executada, mas o registro no banco falhou: {exc}"
