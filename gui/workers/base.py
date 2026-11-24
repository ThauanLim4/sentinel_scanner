"""Infraestrutura de execução assíncrona: QThread + sinais Qt + cancelamento cooperativo."""
from __future__ import annotations

import threading
import time
import traceback

from PySide6.QtCore import QObject, QThread, Signal

from core.logger import get_logger
from ..errors import friendly_error

log = get_logger("gui.workers")

# Threads que não terminaram dentro do prazo de encerramento continuam referenciadas
# até finalizarem (evita destruir um QThread em execução).
_ABANDONED: set["Worker"] = set()


class TaskCancelled(Exception):
    """Levantada pela tarefa quando o cancelamento é observado."""


def check_cancelled(worker: "Worker") -> None:
    if worker.is_cancelled():
        raise TaskCancelled()


class Worker(QThread):
    succeeded = Signal(object)
    failed = Signal(str, str)
    cancelled = Signal()
    progressed = Signal(object)
    status_changed = Signal(str)

    def __init__(self, task, parent=None):
        super().__init__(parent)
        self._task = task
        self._cancel = threading.Event()
        self.on_cancel = None

    # ------------------------------------------------------------------ controle
    def cancel(self) -> None:
        self._cancel.set()
        hook = self.on_cancel
        if hook is not None:
            try:
                hook()
            except Exception:
                log.exception("Falha ao solicitar cancelamento da operação")

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def emit_progress(self, value) -> None:
        self.progressed.emit(value)

    def set_status(self, text: str) -> None:
        self.status_changed.emit(text)

    # ------------------------------------------------------------------ execução
    def run(self) -> None:  # noqa: D401 - contrato do QThread
        try:
            result = self._task(self)
        except TaskCancelled:
            self.cancelled.emit()
            return
        except Exception as exc:
            if self._cancel.is_set():
                self.cancelled.emit()
            else:
                log.error("Operação assíncrona falhou: %s\n%s", exc, traceback.format_exc())
                self.failed.emit(friendly_error(exc), traceback.format_exc())
            return
        self.succeeded.emit(result)


class TaskManager(QObject):
    """Mantém referências às threads vivas e centraliza o encerramento."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._workers: set[Worker] = set()
        self._closed = False

    def start(self, task, *, on_success=None, on_error=None, on_progress=None,
              on_status=None, on_cancelled=None, on_finished=None) -> Worker:
        worker = Worker(task)
        if on_success is not None:
            worker.succeeded.connect(on_success)
        if on_error is not None:
            worker.failed.connect(on_error)
        if on_progress is not None:
            worker.progressed.connect(on_progress)
        if on_status is not None:
            worker.status_changed.connect(on_status)
        if on_cancelled is not None:
            worker.cancelled.connect(on_cancelled)
        if on_finished is not None:
            worker.finished.connect(on_finished)
        self._workers.add(worker)
        worker.finished.connect(lambda w=worker: self._cleanup(w))
        worker.start()
        return worker

    def _cleanup(self, worker: Worker) -> None:
        self._workers.discard(worker)
        _ABANDONED.discard(worker)
        worker.deleteLater()

    def active_count(self) -> int:
        return len(self._workers)

    def is_busy(self) -> bool:
        return bool(self._workers)

    def cancel_all(self) -> None:
        for worker in list(self._workers):
            worker.cancel()

    def shutdown(self, timeout_ms: int = 5000) -> None:
        if self._closed:
            return
        self._closed = True
        workers = list(self._workers)
        for worker in workers:
            worker.cancel()
        deadline = time.monotonic() + max(0, timeout_ms) / 1000
        for worker in workers:
            remaining = max(0, int((deadline - time.monotonic()) * 1000))
            if not worker.wait(remaining):
                log.warning("Thread ainda em execução após o prazo de encerramento: %s", worker)
                _ABANDONED.add(worker)
