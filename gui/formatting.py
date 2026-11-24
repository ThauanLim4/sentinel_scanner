"""Formatação compartilhada pela interface (sem dependência de widgets)."""
from __future__ import annotations

from datetime import datetime, timedelta

RISK_COLORS = {
    "SEGURO": "#22c55e",
    "BAIXO": "#38bdf8",
    "MÉDIO": "#f59e0b",
    "ALTO": "#fb923c",
    "CRÍTICO": "#ef4444",
}
RISK_ORDER = {"SEGURO": 0, "BAIXO": 1, "MÉDIO": 2, "ALTO": 3, "CRÍTICO": 4}

ACTION_LABELS = {
    "quarantine": "Quarentena",
    "quarantine_failed": "Falha na quarentena",
    "quarantine_refused": "Quarentena recusada",
    "quarantine_recover": "Recuperação da quarentena",
    "quarantine_delete": "Exclusão definitiva",
    "quarantine_migrate_legacy": "Migração de item legado",
    "restore": "Restauração",
    "restore_failed": "Falha na restauração",
    "restore_pending": "Restauração pendente",
    "restore_recover": "Recuperação da restauração",
    "defender_update": "Atualização de definições do Defender",
    "defender_scan_quick": "Verificação rápida do Defender",
    "defender_scan_full": "Verificação completa do Defender",
    "process_terminate": "Encerramento de processo",
    "cleanup_delete": "Limpeza de arquivo",
    "cleanup_recycle": "Esvaziamento da Lixeira",
    "startup_disable": "Desativação de inicialização",
    "startup_enable": "Reativação de inicialização",
    "registry_fix": "Correção do Registro",
}


def format_bytes(size) -> str:
    try:
        n = float(size or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def format_duration(seconds) -> str:
    try:
        total = int(max(0, float(seconds)))
    except (TypeError, ValueError):
        return "—"
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def _parse(value):
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def parse_datetime(value):
    """Converte ISO/SQLite em datetime (ou None). Público para filtros da interface."""
    return _parse(value)


def format_datetime(value) -> str:
    dt = _parse(value)
    if not dt:
        return "—"
    return dt.strftime("%d/%m/%Y %H:%M")


def format_time(value) -> str:
    dt = _parse(value)
    return dt.strftime("%H:%M:%S") if dt else "—"


def relative_time(value) -> str:
    dt = _parse(value)
    if not dt:
        return "—"
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    delta = now - dt
    if delta < timedelta(seconds=60):
        return "agora"
    if delta < timedelta(hours=1):
        return f"há {int(delta.total_seconds() // 60)} min"
    if delta < timedelta(days=1):
        return f"há {int(delta.total_seconds() // 3600)} h"
    if delta < timedelta(days=7):
        return f"há {delta.days} dia(s)"
    return format_datetime(value)


def risk_color(risk: str) -> str:
    return RISK_COLORS.get(str(risk), "#919bb0")


def risk_order(risk: str) -> int:
    return RISK_ORDER.get(str(risk), 0)


def action_label(action: str) -> str:
    return ACTION_LABELS.get(str(action), str(action).replace("_", " ").title())


QUARANTINE_STATUS = {
    "quarantined": ("Isolado", "danger"),
    "pending": ("Pendente", "warning"),
    "ready": ("Pronto", "warning"),
    "restoring": ("Restaurando", "accent"),
    "deleting": ("Excluindo", "accent"),
    "restored": ("Restaurado", "safe"),
    "deleted": ("Excluído", "gray"),
    "failed": ("Falhou", "danger"),
}
STATUS_LEVEL_COLORS = {
    "safe": "#22c55e", "warning": "#f59e0b", "danger": "#ef4444",
    "accent": "#38bdf8", "gray": "#919bb0",
}


def quarantine_status(status: str) -> tuple[str, str]:
    """Rótulo e nível visual de um estado real do banco de quarentena."""
    return QUARANTINE_STATUS.get(str(status), (str(status or "Desconhecido"), "gray"))


def status_color(level: str) -> str:
    return STATUS_LEVEL_COLORS.get(str(level), STATUS_LEVEL_COLORS["gray"])


def short_hash(value: str, size: int = 16) -> str:
    value = str(value or "")
    if not value:
        return "—"
    return value if len(value) <= size else value[:size] + "…"
