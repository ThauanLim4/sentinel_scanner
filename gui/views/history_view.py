"""Histórico unificado: varreduras, detecções, quarentena e ações reais do banco.

A leitura é assíncrona e incremental. Não há evento sintético: quando o banco
não registra determinada operação (por exemplo, consultas ao Defender), a
limitação é explicada na própria tela.
"""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from ..components.common import (
    Badge,
    Card,
    InfoBanner,
    MiniStat,
    PageHeader,
    elide,
    make_button,
    make_scroll,
    set_role,
)
from ..components.data_table import Cell, DataTable
from ..components.detail_dialog import DetailDialog
from ..context import AppContext
from ..errors import friendly_error
from ..formatting import format_bytes, format_datetime, format_time
from ..workers.history_worker import CATEGORY_FILTERS, PERIOD_FILTERS, make_history_task
from .base_view import BaseView

CATEGORY_LABELS = {"scans": "Varredura", "findings": "Detecção",
                   "quarantine": "Quarentena", "actions": "Ação"}
RESULT_LABELS = {
    "success": ("Sucesso", "#22c55e"),
    "failure": ("Falha", "#ef4444"),
    "partial": ("Parcial", "#f59e0b"),
    "info": ("Registro", "#38bdf8"),
}


class HistoryView(BaseView):
    KEY = "history"
    TITLE = "Histórico"
    SUBTITLE = "Atividades registradas pelo Sentinel Scanner"

    def __init__(self, context: AppContext, parent=None):
        self._events: list[dict] = []
        self._total = 0
        self._has_more = False
        self._busy = False
        self._worker = None
        self._worker_kind = ""
        self._loaded = False
        self._resetting = True
        super().__init__(context, parent)

    # ------------------------------------------------------------------ layout
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        content = QWidget()
        content.setObjectName("ViewRoot")
        body = QVBoxLayout(content)
        body.setContentsMargins(26, 22, 26, 28)
        body.setSpacing(16)

        self.refresh_button = make_button(
            "Atualizar", "refresh", tooltip="Recarregar do início com os filtros atuais",
            clicked=lambda: self.load(reset=True))
        self.more_button = make_button(
            "Carregar mais", "chevron", tooltip="Buscar registros mais antigos",
            clicked=lambda: self.load(reset=False))
        self.details_button = make_button("Detalhes", "eye", clicked=self._show_selected)
        self.cancel_button = make_button("Cancelar", "stop", clicked=self.cancel)
        body.addWidget(PageHeader(
            self.TITLE, self.SUBTITLE,
            [self.refresh_button, self.more_button, self.details_button, self.cancel_button]))

        self.banner = InfoBanner()
        body.addWidget(self.banner)

        status_card = Card(padding=16, spacing=10)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.status_badge = Badge("Aguardando", "gray")
        self.status_label = QLabel("O histórico ainda não foi carregado.")
        set_role(self.status_label, "muted")
        self.status_label.setWordWrap(True)
        top.addWidget(self.status_badge)
        top.addWidget(self.status_label, 1)
        status_card.body.addLayout(top)
        stats = QHBoxLayout()
        stats.setSpacing(28)
        self.stat_loaded = MiniStat("Eventos carregados", "—")
        self.stat_total = MiniStat("Eventos no filtro", "—")
        self.stat_actions = MiniStat("Ações", "—")
        self.stat_detections = MiniStat("Detecções", "—")
        for stat in (self.stat_loaded, self.stat_total, self.stat_actions, self.stat_detections):
            stats.addWidget(stat)
        stats.addStretch(1)
        status_card.body.addLayout(stats)
        body.addWidget(status_card)

        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Buscar por nome, caminho, ação ou detalhe…")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.returnPressed.connect(lambda: self.load(reset=True))
        self.category_combo = QComboBox()
        for label, _value in CATEGORY_FILTERS:
            self.category_combo.addItem(label)
        self.category_combo.currentIndexChanged.connect(self._on_filter_changed)
        self.period_combo = QComboBox()
        for label, _value in PERIOD_FILTERS:
            self.period_combo.addItem(label)
        self.period_combo.currentIndexChanged.connect(self._on_filter_changed)
        filters.addWidget(self.search_input, 1)
        filters.addWidget(self.category_combo, 0)
        filters.addWidget(self.period_combo, 0)
        body.addLayout(filters)

        table_card = Card(padding=14, spacing=10)
        self.table = DataTable(
            ["Data/hora", "Categoria", "Evento", "Detalhes", "Resultado"],
            empty_icon="history", empty_title="Nenhum evento registrado",
            empty_text="Ajuste os filtros ou execute uma varredura para gerar registros.")
        self.table.set_column_widths([150, 105, 230, 330, 105])
        self.table.row_activated.connect(self._show_entry)
        self.table.selection_changed.connect(self._update_actions)
        table_card.body.addWidget(self.table)
        body.addWidget(table_card)

        note = QLabel(
            "O histórico reflete apenas o que o banco realmente registrou. Atualizações e "
            "verificações do Defender aparecem quando o núcleo confirma a operação; consultas "
            "de estado, ameaças e exclusões não são gravadas. Uma lista vazia não prova "
            "ausência de ameaças nem que nenhuma ação externa ocorreu.")
        set_role(note, "muted2")
        note.setWordWrap(True)
        body.addWidget(note)
        body.addStretch(1)
        root.addWidget(make_scroll(content))
        self._update_actions()

    # ------------------------------------------------------------------ consulta
    def on_activate(self) -> None:
        super().on_activate()
        if not self._loaded:
            self.load(reset=True)

    def _on_filter_changed(self) -> None:
        self.load(reset=True)

    def load(self, reset: bool = True) -> None:
        if self._busy:
            return
        db = self.context.db
        if db is None:
            self._show_error("Banco indisponível",
                             str(self.context.db_error or "Não foi possível abrir o banco."))
            return
        if not reset and not self._has_more:
            return
        offset = 0 if reset else len(self._events)
        self._resetting = reset
        category = CATEGORY_FILTERS[self.category_combo.currentIndex()][1] \
            if 0 <= self.category_combo.currentIndex() < len(CATEGORY_FILTERS) else "all"
        period = PERIOD_FILTERS[self.period_combo.currentIndex()][1] \
            if 0 <= self.period_combo.currentIndex() < len(PERIOD_FILTERS) else "all"
        self._start(make_history_task(db, category, period,
                                      self.search_input.text(), offset=offset), "load")

    def cancel(self) -> None:
        if not self._busy or self._worker is None:
            return
        self.cancel_button.setEnabled(False)
        try:
            self._worker.cancel()
        except RuntimeError:
            pass

    def _start(self, task, kind: str) -> None:
        self._busy = True
        self._worker_kind = kind
        self.status_badge.setText("Consultando")
        self.status_badge.set_level("accent")
        self.status_label.setText("Lendo registros do banco…")
        try:
            self._worker = self.tasks.start(
                task, on_success=self._on_success, on_error=self._on_error,
                on_status=self._on_status, on_cancelled=self._on_cancelled,
                on_finished=self._on_finished)
        except Exception as exc:
            self._busy = False
            self._show_error("Não foi possível consultar o histórico", friendly_error(exc))

    def _on_status(self, text: str) -> None:
        self.status_label.setText(text)

    def _on_success(self, result) -> None:
        if not isinstance(result, dict) or not isinstance(result.get("events"), list):
            self._on_error("O banco retornou um histórico em formato inesperado.", "")
            return
        events = [e for e in result["events"] if isinstance(e, dict)]
        self._events = events if self._resetting else self._events + events
        self._total = int(result.get("total") or len(self._events))
        self._has_more = bool(result.get("has_more"))
        self._loaded = True
        self.status_badge.setText("Atualizado")
        self.status_badge.set_level("safe")
        self.status_label.setText(
            f"{len(events)} evento(s) carregado(s); {self._total} no filtro.")
        self._render()
        if not self._events:
            self.banner.set_message("info", "Nenhum evento para o filtro",
                                    "Isso significa ausência de registros no banco, não uma "
                                    "garantia de que nada aconteceu.")
        else:
            self.banner.clear()

    def _on_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Histórico falhou: %s", message)
        self.status_badge.setText("Falhou")
        self.status_badge.set_level("danger")
        self.status_label.setText(message)
        self.banner.set_message("danger", "Histórico indisponível", message)
        self.error("Histórico", message)

    def _show_error(self, title: str, message: str) -> None:
        self._busy = False
        self.status_badge.setText("Indisponível")
        self.status_badge.set_level("danger")
        self.status_label.setText(message)
        self.banner.set_message("danger", title, message)
        self.table.clear()
        self._update_actions()
        self.error(title, message)

    def _on_cancelled(self) -> None:
        self.status_badge.setText("Cancelado")
        self.status_badge.set_level("warning")
        self.status_label.setText("Consulta cancelada; os eventos anteriores foram mantidos.")
        self.banner.set_message("warning", "Consulta cancelada", "Nenhum resultado parcial foi aplicado.")
        self.warn("Histórico", "Consulta cancelada")

    def _on_finished(self) -> None:
        self._busy = False
        self._worker = None
        self._worker_kind = ""
        self._update_actions()

    # ------------------------------------------------------------------ tabela
    def _render(self) -> None:
        rows, payloads = [], []
        for event in self._events:
            label, color = RESULT_LABELS.get(str(event.get("result")),
                                             ("—", "#919bb0"))
            rows.append([
                Cell(format_datetime(event.get("ts")),
                     sort_key=str(event.get("ts") or "")),
                Cell(CATEGORY_LABELS.get(str(event.get("category")),
                                         str(event.get("category") or "—"))),
                Cell(elide(str(event.get("title") or "—"), 48),
                     tooltip=str(event.get("title") or "")),
                Cell(elide(str(event.get("detail") or ""), 70),
                     tooltip=str(event.get("detail") or "")),
                Cell(label, color=color, bold=True),
            ])
            payloads.append(event)
        self.table.set_rows(rows, payloads)
        self._render_stats()

    def _render_stats(self) -> None:
        self.stat_loaded.set_value(str(len(self._events)) if self._loaded else "—")
        self.stat_total.set_value(str(self._total) if self._loaded else "—")
        self.stat_actions.set_value(
            str(sum(1 for e in self._events if e.get("category") == "actions")) if self._loaded else "—")
        self.stat_detections.set_value(
            str(sum(1 for e in self._events if e.get("category") == "findings")) if self._loaded else "—")
        self.more_button.setEnabled(not self._busy and self._loaded and self._has_more)

    def _update_actions(self) -> None:
        self.details_button.setEnabled(not self._busy and self.table.selected_payload() is not None)
        self.refresh_button.setEnabled(not self._busy)
        self.cancel_button.setEnabled(self._busy)
        self.more_button.setEnabled(not self._busy and self._has_more)

    def _selected(self) -> dict | None:
        payload = self.table.selected_payload()
        return payload if isinstance(payload, dict) else None

    def _show_selected(self) -> None:
        event = self._selected()
        if event is not None:
            self._show_entry(event)

    def _show_entry(self, event) -> None:
        if not isinstance(event, dict):
            return
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        label, _color = RESULT_LABELS.get(str(event.get("result")), ("—", "#919bb0"))
        category = str(event.get("category") or "")
        fields = [
            ("Data/hora", format_datetime(event.get("ts"))),
            ("Hora", format_time(event.get("ts"))),
            ("Categoria", CATEGORY_LABELS.get(category, category or "—")),
            ("Evento", str(event.get("title") or "—")),
            ("Resultado", label),
            ("Detalhes", str(event.get("detail") or "—")),
        ]
        if category == "scans":
            fields += [("Tipo", str(payload.get("kind") or "—")),
                       ("Início", format_datetime(payload.get("started"))),
                       ("Fim", format_datetime(payload.get("finished"))),
                       ("Arquivos", str(int(payload.get("files_scanned") or 0))),
                       ("Processos", str(int(payload.get("processes_scanned") or 0))),
                       ("Status", str(payload.get("status") or "—"))]
        elif category == "findings":
            fields += [("Caminho", str(payload.get("path") or "—")),
                       ("SHA-256", str(payload.get("sha256") or "—")),
                       ("Risco", str(payload.get("risk") or "—")),
                       ("Pontuação", str(int(payload.get("score") or 0)))]
        elif category == "quarantine":
            fields += [("ID", str(payload.get("id") or "—")),
                       ("Caminho original", str(payload.get("original_path") or "—")),
                       ("Tamanho", format_bytes(payload.get("size"))),
                       ("SHA-256", str(payload.get("sha256") or "—")),
                       ("Estado", str(payload.get("status") or "—"))]
        elif category == "actions":
            fields += [("Ação", str(payload.get("action") or "—")),
                       ("Alvo", str(payload.get("target") or "—")),
                       ("Sucesso", "Sim" if bool(payload.get("success")) else "Não")]

        sections = []
        if category == "findings":
            try:
                raw = json.loads(payload.get("evidence_json") or "{}")
            except (TypeError, ValueError):
                raw = {}
            evidences = raw.get("evidences") if isinstance(raw, dict) else None
            lines = []
            for evidence in evidences or []:
                if isinstance(evidence, dict):
                    lines.append(f"[{int(evidence.get('weight') or 0):+d}] "
                                 f"{evidence.get('description', '')}")
            sections.append(("Evidências registradas", lines or "Nenhuma evidência gravada."))
        DetailDialog(
            self, str(event.get("title") or "Histórico"),
            "Registro lido do banco; nenhum dado foi acrescentado.",
            fields=fields, sections=sections,
            note="Indicadores heurísticos não confirmam malware por si só.",
        ).exec()
