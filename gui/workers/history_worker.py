"""Carregamento incremental do histórico unificado a partir do banco real.

Nenhum evento é inventado: cada linha corresponde a um registro de varredura,
detecção, quarentena ou ação já persistido. Consultas do Defender não são
registradas pelo núcleo e, portanto, não aparecem aqui.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from ..formatting import action_label, parse_datetime, quarantine_status
from .base import check_cancelled

CATEGORY_FILTERS = [
    ("Todas as categorias", "all"),
    ("Varreduras", "scans"),
    ("Detecções", "findings"),
    ("Quarentena", "quarantine"),
    ("Ações e operações", "actions"),
]
PERIOD_FILTERS = [
    ("Qualquer período", "all"),
    ("Últimas 24 horas", "24h"),
    ("Últimos 7 dias", "7d"),
    ("Últimos 30 dias", "30d"),
]
PERIOD_DAYS = {"24h": 1, "7d": 7, "30d": 30}


def _name(path: str) -> str:
    return Path(path or "").name or str(path or "—")


def _events_from_scans(rows: list) -> list[dict]:
    out = []
    for row in rows:
        status = str(row.get("status") or "")
        result = {"completed": "success", "failed": "failure"}.get(status, "partial")
        out.append({
            "category": "scans", "ts": row.get("started") or row.get("finished") or "",
            "title": f"Varredura #{row.get('id')} ({row.get('kind') or '—'})",
            "detail": (f"status={status or '—'}; {int(row.get('files_scanned') or 0)} arquivo(s); "
                       f"{int(row.get('processes_scanned') or 0)} processo(s); "
                       f"finalizada em {row.get('finished') or '—'}"),
            "result": result, "payload": dict(row),
        })
    return out


def _events_from_findings(rows: list) -> list[dict]:
    return [{
        "category": "findings", "ts": row.get("ts") or "",
        "title": f"Detecção: {_name(str(row.get('path') or ''))}",
        "detail": (f"risco={row.get('risk') or '—'}; pontuação={int(row.get('score') or 0)}; "
                   f"scan #{row.get('scan_id') or '—'}; status={row.get('status') or '—'}"),
        "result": "info", "payload": dict(row),
    } for row in rows]


def _events_from_quarantine(rows: list) -> list[dict]:
    out = []
    for row in rows:
        status = str(row.get("status") or "")
        label, _level = quarantine_status(status)
        result = {"failed": "failure", "restored": "success", "deleted": "success",
                  "quarantined": "success"}.get(status, "partial")
        out.append({
            "category": "quarantine", "ts": row.get("ts") or "",
            "title": f"Quarentena: {_name(str(row.get('original_path') or ''))}",
            "detail": (f"id={row.get('id')}; estado={label}; "
                       f"tamanho={int(row.get('size') or 0)} bytes"),
            "result": result, "payload": dict(row),
        })
    return out


def _events_from_actions(rows: list) -> list[dict]:
    return [{
        "category": "actions", "ts": row.get("ts") or "",
        "title": action_label(str(row.get("action") or "")),
        "detail": f"{row.get('target') or '—'} — {row.get('detail') or ''}".strip(),
        "result": "success" if bool(row.get("success")) else "failure",
        "payload": dict(row),
    } for row in rows]


def make_history_task(db, category: str = "all", period: str = "all", search: str = "",
                      offset: int = 0, limit: int = 100):
    """Monta uma página cronológica; ``offset`` permite carregamento incremental."""
    valid_categories = {value for _label, value in CATEGORY_FILTERS}
    valid_periods = {value for _label, value in PERIOD_FILTERS}
    category = category if category in valid_categories else "all"
    period = period if period in valid_periods else "all"
    offset, limit = max(0, int(offset)), max(1, int(limit))
    fetch = offset + limit
    needle = str(search or "").strip().casefold()

    def task(worker):
        worker.set_status("Consultando o histórico…")
        check_cancelled(worker)
        events: list[dict] = []
        if category in ("all", "scans"):
            events += _events_from_scans(db.list_scans(limit=fetch))
        if category in ("all", "findings"):
            # Consultas com limite evitam carregar todas as detecções de uma vez.
            events += _events_from_findings(db.list_findings(limit=fetch))
        if category in ("all", "quarantine"):
            events += _events_from_quarantine(db.list_quarantine(status=None, limit=fetch))
        if category in ("all", "actions"):
            events += _events_from_actions(db.list_actions(limit=fetch))
        check_cancelled(worker)

        cutoff = None
        if period in PERIOD_DAYS:
            cutoff = datetime.now() - timedelta(days=PERIOD_DAYS[period])
        filtered = []
        for event in events:
            ts = parse_datetime(event.get("ts"))
            if period != "all" and (ts is None or (cutoff and ts.replace(tzinfo=None) < cutoff)):
                continue
            payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
            haystack = " ".join(
                [str(event.get(k) or "") for k in ("title", "detail", "ts")] +
                [str(v or "") for v in payload.values()]).casefold()
            if needle and needle not in haystack:
                continue
            filtered.append(event)
        filtered.sort(key=lambda e: str(e.get("ts") or ""), reverse=True)
        page = filtered[offset:offset + limit]
        return {"events": page, "total": len(filtered),
                "has_more": len(filtered) > offset + limit}
    return task
