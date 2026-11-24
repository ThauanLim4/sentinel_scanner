"""Tela de Processos: leitura assíncrona, filtros, detalhes e encerramento confirmado.

A tela apenas orquestra o `ProcessAnalyzer`. Nenhum processo é encerrado sem
confirmação explícita; o núcleo ainda recusa processos críticos, serviços do
Windows e PIDs reutilizados. A análise profunda (abrir binários e consultar
assinaturas) é opcional para manter a atualização rápida.
"""
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from core.process_analyzer import ProcessInfo, is_critical_process
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
from ..formatting import format_bytes, format_datetime, format_time, risk_color, risk_order
from ..workers.process_worker import make_snapshot_task, make_terminate_task
from .base_view import BaseView

REFRESH_TTL = 20.0
MAX_ROWS = 600

RISK_FILTERS = [
    ("Todos os riscos", 0),
    ("Médio ou superior", 2),
    ("Alto e crítico", 3),
    ("Somente seguros", -1),
]


class ProcessesView(BaseView):
    KEY = "processes"
    TITLE = "Processos"
    SUBTITLE = "Processos ativos, indicadores e encerramento seguro"

    def __init__(self, context: AppContext, parent=None):
        self._entries: list[ProcessInfo] = []
        self._loaded = False
        self._loading = False
        self._terminating = False
        self._checked_at = 0.0
        self._last_deep = False
        self._terminated_ok = False
        self._terminated_pid: int | None = None
        super().__init__(context, parent)

    # ------------------------------------------------------------------ layout
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        content = QWidget()
        content.setObjectName("ViewRoot")
        self.body = QVBoxLayout(content)
        self.body.setContentsMargins(26, 22, 26, 28)
        self.body.setSpacing(16)

        self.refresh_button = make_button(
            "Atualizar", "refresh", tooltip="Reler a lista de processos ativos",
            clicked=lambda: self.refresh(force=True))
        self.details_button = make_button("Detalhes", "eye", clicked=self._show_selected)
        self.terminate_button = make_button(
            "Encerrar processo", "power", kind="danger",
            tooltip="Encerrar o processo selecionado (exige confirmação)",
            clicked=self._terminate_selected)
        self.body.addWidget(PageHeader(
            self.TITLE, self.SUBTITLE,
            [self.refresh_button, self.details_button, self.terminate_button]))

        self.banner = InfoBanner()
        self.body.addWidget(self.banner)

        # ------------------------------------------------------------- status
        status_card = Card(padding=16, spacing=10)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.status_badge = Badge("Aguardando", "gray")
        self.status_label = QLabel("A lista ainda não foi carregada.")
        set_role(self.status_label, "muted")
        self.status_label.setWordWrap(True)
        self.deep_checkbox = QCheckBox("Análise profunda")
        self.deep_checkbox.setToolTip(
            "Abrir os binários e consultar assinaturas digitais. É mais lenta, porém "
            "detecta mais indicadores. O modo rápido apenas lê nome, caminho, CPU e memória.")
        top.addWidget(self.status_badge)
        top.addWidget(self.status_label, 1)
        top.addWidget(self.deep_checkbox)
        status_card.body.addLayout(top)

        stats = QHBoxLayout()
        stats.setSpacing(28)
        self.stat_total = MiniStat("Processos", "—")
        self.stat_risk = MiniStat("Em risco (médio+)", "—")
        self.stat_high = MiniStat("Alto e crítico", "—")
        self.stat_memory = MiniStat("Memória somada", "—")
        for widget in (self.stat_total, self.stat_risk, self.stat_high, self.stat_memory):
            stats.addWidget(widget)
        stats.addStretch(1)
        status_card.body.addLayout(stats)
        self.body.addWidget(status_card)

        # ------------------------------------------------------------ filtros
        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filtrar por nome, PID, usuário ou caminho…")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._render)
        self.risk_filter = QComboBox()
        for label, _level in RISK_FILTERS:
            self.risk_filter.addItem(label)
        self.risk_filter.currentIndexChanged.connect(self._render)
        filters.addWidget(self.search_input, 1)
        filters.addWidget(self.risk_filter, 0)
        self.body.addLayout(filters)

        table_card = Card(padding=14, spacing=10)
        self.table = DataTable(
            ["PID", "Nome", "Risco", "CPU %", "RAM", "Usuário", "Caminho"],
            empty_icon="process",
            empty_title="Nenhum processo carregado",
            empty_text="Use Atualizar para ler os processos ativos.",
        )
        self.table.setMinimumHeight(430)
        self.table.row_activated.connect(self._show_entry)
        self.table.selection_changed.connect(self._update_actions)
        self.table.set_column_widths([70, 160, 85, 75, 95, 130, 300])
        self.table.table.horizontalHeader().setSectionResizeMode(
            6, QHeaderView.ResizeMode.Stretch)
        table_card.body.addWidget(self.table)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.open_button = make_button("Abrir pasta", "folder", clicked=self._open_selected)
        actions.addWidget(self.open_button)
        actions.addStretch(1)
        note = QLabel("Indicadores são heurísticos e não confirmam malware. O encerramento "
                      "exige confirmação; processos críticos e serviços do Windows são recusados "
                      "pelo núcleo do Sentinel.")
        set_role(note, "muted2")
        note.setWordWrap(True)
        actions.addWidget(note, 2)
        table_card.body.addLayout(actions)
        self.body.addWidget(table_card)

        self.footer_label = QLabel("")
        set_role(self.footer_label, "muted2")
        self.footer_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.body.addWidget(self.footer_label)
        self.body.addStretch(1)

        root.addWidget(make_scroll(content))
        self._update_actions()

    # ------------------------------------------------------------------ dados
    def on_activate(self) -> None:
        super().on_activate()
        stale = not self._checked_at or (time.monotonic() - self._checked_at) >= REFRESH_TTL
        if not self._loaded or stale:
            self.refresh(force=False)

    def refresh(self, force: bool = True) -> None:
        if self._loading or self._terminating:
            return
        if not force and self._checked_at and \
                (time.monotonic() - self._checked_at) < REFRESH_TTL:
            return
        try:
            analyzer = self.context.process_analyzer()
        except Exception as exc:
            self._show_error("Analisador de processos indisponível", friendly_error(exc))
            return
        deep = self.deep_checkbox.isChecked()
        self._last_deep = deep
        self._loading = True
        self._set_busy_ui(True, "Lendo processos ativos…")
        self.tasks.start(
            make_snapshot_task(analyzer, deep=deep,
                               signatures="suspicious" if deep else "none",
                               cpu_interval=0.4),
            on_success=self._on_entries,
            on_error=self._on_error,
            on_status=self._on_status,
            on_cancelled=self._on_cancelled,
            on_finished=self._on_refresh_finished,
        )

    def _on_status(self, text: str) -> None:
        self.status_label.setText(text)

    def _on_entries(self, entries) -> None:
        if not isinstance(entries, list):
            self._on_error("O núcleo retornou uma resposta inesperada ao listar processos.", "")
            return
        self._entries = entries
        self._loaded = True
        self._checked_at = time.monotonic()
        self.status_badge.setText("Atualizado")
        self.status_badge.set_level("safe")
        mode = "profunda (binários e assinaturas)" if self._last_deep else "rápida"
        self.status_label.setText(
            f"{len(entries)} processo(s) lido(s) em análise {mode}.")
        self._render()
        if not entries:
            self.banner.set_message(
                "warning", "Nenhum processo pôde ser lido",
                "O Windows pode negar acesso à lista de processos sem privilégios de "
                "administrador. Isso não significa que não existam processos ativos.")
        else:
            self.banner.clear()
        self.footer_label.setText(
            f"Última atualização: {format_time(datetime.now())}  •  "
            "Indicadores são heurísticos; nenhuma ação foi executada.")

    def _on_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Leitura de processos falhou: %s", message)
        self._show_error("Não foi possível analisar os processos", message)

    def _show_error(self, title: str, message: str) -> None:
        self._loading = False
        self.status_badge.setText("Falhou")
        self.status_badge.set_level("danger")
        self.status_label.setText(message)
        self.banner.set_message("danger", title, message)
        self.table.set_empty("alert", "Processos indisponíveis",
                             "Não foi possível ler a lista de processos.")
        self.table.clear()
        self.error(title, message)

    def _on_cancelled(self) -> None:
        self.status_badge.setText("Cancelado")
        self.status_badge.set_level("warning")
        self.status_label.setText("A leitura foi cancelada; a lista anterior foi mantida.")
        self.banner.set_message("warning", "Leitura cancelada",
                                "Nenhum resultado parcial foi aplicado.")
        self.warn("Leitura cancelada", "A lista de processos não foi atualizada.")

    def _on_refresh_finished(self) -> None:
        self._loading = False
        self._update_actions()

    def _set_busy_ui(self, busy: bool, status: str) -> None:
        self.refresh_button.setEnabled(not busy)
        self.deep_checkbox.setEnabled(not busy)
        self.status_badge.setText("Analisando" if busy else "Pronto")
        self.status_badge.set_level("accent" if busy else "gray")
        self.status_label.setText(status)
        self._update_actions()

    # ------------------------------------------------------------------ filtros
    def _risk_threshold(self) -> int:
        index = self.risk_filter.currentIndex()
        return RISK_FILTERS[index][1] if 0 <= index < len(RISK_FILTERS) else 0

    def _visible_entries(self) -> list[ProcessInfo]:
        text = self.search_input.text().strip().casefold()
        threshold = self._risk_threshold()
        out = []
        for info in self._entries:
            level = int(info.risk)
            if threshold == -1:
                if level != 0:
                    continue
            elif level < threshold:
                continue
            haystack = f"{info.pid} {info.name} {info.exe} {info.username}".casefold()
            if text and text not in haystack:
                continue
            out.append(info)
        return out

    def _render(self) -> None:
        if not isinstance(self._entries, list):
            self._entries = []
        visible = self._visible_entries()[:MAX_ROWS]
        if self._entries and not visible:
            self.table.set_empty("info", "Nenhum processo para o filtro",
                                 "Ajuste a busca ou selecione outro nível de risco.")
        elif not self._entries:
            self.table.set_empty("process", "Nenhum processo carregado",
                                 "Use Atualizar para ler os processos ativos.")

        rows, payloads = [], []
        for info in visible:
            risk = info.risk.label
            path = str(info.exe or "—")
            rows.append([
                Cell(str(info.pid), sort_key=int(info.pid)),
                Cell(str(info.name or "—"), tooltip=info.name),
                Cell(risk, sort_key=risk_order(risk), color=risk_color(risk), bold=True),
                Cell(f"{float(info.cpu_percent or 0.0):.1f}",
                     sort_key=float(info.cpu_percent or 0.0)),
                Cell(format_bytes(info.rss), sort_key=int(info.rss or 0)),
                Cell(elide(info.username or "—", 28), tooltip=info.username),
                Cell(elide(path, 72), tooltip=path),
            ])
            payloads.append(info)
        self.table.set_rows(rows, payloads)
        self._render_stats()
        self._update_actions()

    def _render_stats(self) -> None:
        entries = self._entries
        risk = sum(1 for e in entries if int(e.risk) >= 2)
        high = sum(1 for e in entries if int(e.risk) >= 3)
        memory = sum(int(e.rss or 0) for e in entries)
        self.stat_total.set_value(str(len(entries)) if self._loaded else "—")
        self.stat_risk.set_value(str(risk) if self._loaded else "—")
        self.stat_high.set_value(str(high) if self._loaded else "—")
        self.stat_memory.set_value(format_bytes(memory) if self._loaded else "—")

    # ------------------------------------------------------------------ ações
    def _update_actions(self) -> None:
        payload = self.table.selected_payload()
        selected = isinstance(payload, ProcessInfo)
        busy = self._loading or self._terminating
        self.details_button.setEnabled(selected)
        self.open_button.setEnabled(selected and bool(payload.exe))
        critical = selected and is_critical_process(payload.name, payload.exe, payload.pid)
        self.terminate_button.setEnabled(selected and not busy and not critical)
        if critical:
            self.terminate_button.setToolTip(
                "Processo crítico do Windows ou do próprio Sentinel: não pode ser encerrado.")
        elif selected and busy:
            self.terminate_button.setToolTip("Aguarde a operação atual terminar.")
        else:
            self.terminate_button.setToolTip(
                "Encerrar o processo selecionado (exige confirmação)")

    def _show_selected(self) -> None:
        payload = self.table.selected_payload()
        if isinstance(payload, ProcessInfo):
            self._show_entry(payload)

    def _show_entry(self, info) -> None:
        if not isinstance(info, ProcessInfo):
            return
        data = info.to_dict()
        evidence_lines = []
        if info.finding is not None:
            evidence_lines = [
                f"[{int(e.weight):+d}] {e.description}"
                for e in sorted(info.finding.evidences, key=lambda e: -int(e.weight))
            ]
        fields = [
            ("PID", info.pid),
            ("Nome", info.name),
            ("Executável", info.exe),
            ("Usuário", info.username),
            ("Risco", info.risk.label),
            ("Pontuação", info.finding.score if info.finding else 0),
            ("CPU", f"{float(info.cpu_percent or 0.0):.1f} %"),
            ("Memória", format_bytes(info.rss)),
            ("Iniciado em", format_datetime(data.get("started"))),
            ("Processo-pai", f"{info.parent_name or '—'} (PID {info.ppid})"),
            ("Fabricante", info.company),
            ("Assinatura digital", info.signature),
            ("Linha de comando", " ".join(info.cmdline) if info.cmdline else ""),
        ]
        critical = is_critical_process(info.name, info.exe, info.pid)
        note = ("Processo crítico do Windows ou do próprio Sentinel: o encerramento é "
                "recusado pelo núcleo." if critical else
                "Indicadores heurísticos não confirmam malware. Encerrar um processo pode "
                "interromper um programa legítimo; revise as evidências antes de agir.")
        DetailDialog(
            self,
            f"Processo {info.name} (PID {info.pid})",
            "Informações lidas do sistema no momento da análise. Nenhuma ação foi executada.",
            fields=fields,
            sections=[("Indicadores", evidence_lines or "Nenhum indicador relevante encontrado.")],
            note=note,
        ).exec()

    def _open_selected(self) -> None:
        payload = self.table.selected_payload()
        if not isinstance(payload, ProcessInfo) or not payload.exe:
            return
        parent = Path(payload.exe).parent
        if not parent.is_dir():
            self.warn("Pasta indisponível", "O diretório deste processo não existe mais.")
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(parent))):
            self.warn("Não foi possível abrir a pasta", str(parent))

    def _terminate_selected(self) -> None:
        payload = self.table.selected_payload()
        if not isinstance(payload, ProcessInfo) or self._terminating:
            return
        if is_critical_process(payload.name, payload.exe, payload.pid):
            self.warn("Processo protegido",
                      "O núcleo do Sentinel recusa encerrar processos críticos do Windows "
                      "ou o próprio programa.")
            return
        try:
            analyzer = self.context.process_analyzer()
        except Exception as exc:
            self.error("Analisador de processos indisponível", friendly_error(exc))
            return
        details = (f"PID: {payload.pid}\nNome: {payload.name}\n"
                   f"Executável: {payload.exe or '—'}\nRisco: {payload.risk.label}\n\n"
                   "Processos filhos não serão encerrados automaticamente.")
        if not self.confirm(
            "Encerrar processo",
            "O processo será encerrado. Trabalho não salvo pode ser perdido e o programa "
            "pode ser reiniciado automaticamente pelo sistema ou por outro serviço.",
            details,
            danger=True,
            confirm_text="Encerrar processo",
            require_ack=True,
            ack_text="Entendo que o processo será encerrado e que isso pode afetar o sistema.",
        ):
            return
        self._terminating = True
        self._terminated_ok = False
        self._terminated_pid = None
        self.status_badge.setText("Encerrando")
        self.status_badge.set_level("accent")
        self.status_label.setText(f"Encerrando {payload.name} (PID {payload.pid})…")
        self.banner.clear()
        self._update_actions()
        self.tasks.start(
            make_terminate_task(analyzer, payload),
            on_success=self._on_terminate_success,
            on_error=self._on_terminate_error,
            on_status=self._on_status,
            on_finished=self._on_terminate_finished,
        )

    def _on_terminate_success(self, result) -> None:
        self._terminated_ok = True
        info = result if isinstance(result, dict) else {}
        name = info.get("name") or "processo"
        count = info.get("terminated")
        extra = f" {count} processo(s) encerrado(s)." if isinstance(count, int) and count > 1 else ""
        try:
            pid = int(info.get("pid"))
        except (TypeError, ValueError):
            pid = None
        if pid is None or count != 0:
            self._terminated_pid = pid
        self.success("Processo encerrado", f"{name} foi encerrado pelo núcleo.{extra}")
        self.banner.set_message(
            "success", "Processo encerrado",
            "A operação foi confirmada pelo núcleo; a lista local foi atualizada.")

    def _on_terminate_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Encerramento de processo falhou: %s", message)
        self.banner.set_message("danger", "Não foi possível encerrar o processo", message)
        self.error("Não foi possível encerrar o processo", message)

    def _on_terminate_finished(self) -> None:
        self._terminating = False
        if self._terminated_ok:
            if self._terminated_pid is not None:
                self._entries = [e for e in self._entries if e.pid != self._terminated_pid]
            self.status_badge.setText("Atualizado")
            self.status_badge.set_level("safe")
            self.status_label.setText(
                f"{len(self._entries)} processo(s) na lista após o encerramento confirmado.")
            self._render_stats()
            self._render()
        else:
            self.status_badge.setText("Falhou")
            self.status_badge.set_level("danger")
        self._update_actions()
