"""Tela de Inicialização: análise e desativação reversível de persistência.

A coleta é somente leitura e pode ser lenta (Registro, pastas, serviços, tarefas e
drivers). Desativar/reativar é executado pelo `StartupManager`, sempre com
confirmação explícita; itens críticos exigem uma confirmação adicional e drivers
não podem ser alterados por esta ferramenta.
"""
from __future__ import annotations

import time
from datetime import datetime

from PySide6.QtCore import Qt
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

from core.startup_analyzer import StartupEntry, StartupManager
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
from ..formatting import format_time, risk_color, risk_order
from ..workers.startup_worker import (
    make_startup_disable_task,
    make_startup_enable_task,
    make_startup_task,
)
from .base_view import BaseView

KIND_LABELS = {
    "run": "Registro (Run)",
    "runonce": "Registro (RunOnce)",
    "run_policy": "Política de Registro",
    "startup_folder": "Pasta de Inicialização",
    "service": "Serviço",
    "task": "Tarefa Agendada",
    "driver": "Driver",
}
KIND_FILTERS = [
    ("Todos os tipos", ()),
    ("Registro", ("run", "runonce")),
    ("Políticas de Registro", ("run_policy",)),
    ("Pasta de Inicialização", ("startup_folder",)),
    ("Serviços", ("service",)),
    ("Tarefas agendadas", ("task",)),
    ("Drivers", ("driver",)),
]
RISK_FILTERS = [("Todos os riscos", 0), ("Médio ou superior", 2), ("Alto e crítico", 3)]
REMOVED_KINDS = ("runonce", "run_policy")


class StartupView(BaseView):
    KEY = "startup"
    TITLE = "Inicialização"
    SUBTITLE = "Mecanismos de inicialização do Windows (alterações reversíveis e confirmadas)"

    def __init__(self, context: AppContext, parent=None):
        self._entries: list[StartupEntry] = []
        self._loaded = False
        self._busy = False
        self._worker = None
        self._mutation = ""
        self._checked_at = 0.0
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
            "Analisar novamente", "refresh",
            tooltip="Reler Registro, pastas, serviços, tarefas e drivers",
            clicked=lambda: self.refresh(force=True))
        self.details_button = make_button("Detalhes", "eye", clicked=self._show_selected)
        self.disable_button = make_button(
            "Desativar", "stop", kind="danger",
            tooltip="Desativar a entrada selecionada (exige confirmação)",
            clicked=self._disable_selected)
        self.enable_button = make_button(
            "Reativar", "restore",
            tooltip="Reativar a entrada selecionada (exige confirmação)",
            clicked=self._enable_selected)
        self.body.addWidget(PageHeader(
            self.TITLE, self.SUBTITLE,
            [self.refresh_button, self.details_button,
             self.disable_button, self.enable_button]))

        self.banner = InfoBanner()
        self.body.addWidget(self.banner)

        # ------------------------------------------------------------- status
        status_card = Card(padding=16, spacing=10)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.status_badge = Badge("Aguardando", "gray")
        self.status_label = QLabel("A análise ainda não foi executada.")
        set_role(self.status_label, "muted")
        self.status_label.setWordWrap(True)
        self.deep_checkbox = QCheckBox("Análise profunda")
        self.deep_checkbox.setChecked(True)
        self.deep_checkbox.setToolTip(
            "Analisar o conteúdo dos binários e consultar assinaturas digitais. "
            "É mais lenta, porém encontra mais indicadores.")
        self.cancel_button = make_button(
            "Cancelar análise", "stop", tooltip="Descartar o resultado desta análise",
            clicked=self.cancel_analysis)
        self.cancel_button.setEnabled(False)
        top.addWidget(self.status_badge)
        top.addWidget(self.status_label, 1)
        top.addWidget(self.deep_checkbox)
        top.addWidget(self.cancel_button)
        status_card.body.addLayout(top)

        stats = QHBoxLayout()
        stats.setSpacing(28)
        self.stat_total = MiniStat("Entradas", "—")
        self.stat_enabled = MiniStat("Habilitadas", "—")
        self.stat_high = MiniStat("Alto e crítico", "—")
        self.stat_services = MiniStat("Serviços", "—")
        self.stat_drivers = MiniStat("Drivers", "—")
        for widget in (self.stat_total, self.stat_enabled, self.stat_high,
                       self.stat_services, self.stat_drivers):
            stats.addWidget(widget)
        stats.addStretch(1)
        status_card.body.addLayout(stats)
        self.body.addWidget(status_card)

        # ------------------------------------------------------------ filtros
        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filtrar por nome, comando ou local…")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._render)
        self.kind_filter = QComboBox()
        for label, _kinds in KIND_FILTERS:
            self.kind_filter.addItem(label)
        self.kind_filter.currentIndexChanged.connect(self._render)
        self.risk_filter = QComboBox()
        for label, _level in RISK_FILTERS:
            self.risk_filter.addItem(label)
        self.risk_filter.currentIndexChanged.connect(self._render)
        filters.addWidget(self.search_input, 1)
        filters.addWidget(self.kind_filter, 0)
        filters.addWidget(self.risk_filter, 0)
        self.body.addLayout(filters)

        table_card = Card(padding=14, spacing=10)
        self.table = DataTable(
            ["Situação", "Tipo", "Nome", "Risco", "Local", "Comando"],
            empty_icon="startup",
            empty_title="Nenhuma entrada analisada",
            empty_text="Use Analisar novamente para ler os mecanismos de inicialização.",
        )
        self.table.setMinimumHeight(430)
        self.table.row_activated.connect(self._show_entry)
        self.table.selection_changed.connect(self._update_actions)
        self.table.set_column_widths([90, 145, 175, 85, 210, 300])
        self.table.table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch)
        table_card.body.addWidget(self.table)

        note = QLabel("Desativar não exclui serviços nem toca em drivers. Entradas Run/Startup "
                      "usam o mesmo mecanismo do Gerenciador de Tarefas; RunOnce e políticas "
                      "são removidas somente após backup .reg. Toda alteração exige confirmação.")
        set_role(note, "muted2")
        note.setWordWrap(True)
        table_card.body.addWidget(note)
        self.body.addWidget(table_card)

        self.footer_label = QLabel("")
        set_role(self.footer_label, "muted2")
        self.footer_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.body.addWidget(self.footer_label)
        self.body.addStretch(1)

        root.addWidget(make_scroll(content))
        self._update_actions()

    # ------------------------------------------------------------------ análise
    def on_activate(self) -> None:
        super().on_activate()
        stale = not self._checked_at or (time.monotonic() - self._checked_at) >= 300
        if not self._loaded or stale:
            self.refresh(force=False)

    def refresh(self, force: bool = True) -> None:
        if self._busy:
            return
        if not force and self._checked_at and \
                (time.monotonic() - self._checked_at) < 300:
            return
        try:
            analyzer = self.context.make_startup_analyzer()
        except Exception as exc:
            self._show_error("Analisador de inicialização indisponível", friendly_error(exc))
            return
        self._busy = True
        self._set_busy_ui(True, "Coletando entradas de inicialização…")
        self.banner.set_message(
            "info", "Análise em andamento",
            "A leitura de Registro, serviços e tarefas agendadas pode levar alguns minutos. "
            "Nenhuma alteração está sendo feita.")
        self.cancel_button.setEnabled(True)
        try:
            self._worker = self.tasks.start(
                make_startup_task(analyzer, deep=self.deep_checkbox.isChecked()),
                on_success=self._on_entries,
                on_error=self._on_error,
                on_status=self._on_status,
                on_cancelled=self._on_cancelled,
                on_finished=self._on_finished,
            )
        except Exception as exc:
            self._busy = False
            self._show_error("Não foi possível iniciar a análise", friendly_error(exc))

    def cancel_analysis(self) -> None:
        if not self._busy or self._worker is None:
            return
        self.cancel_button.setEnabled(False)
        self.status_label.setText("Cancelamento solicitado; o resultado será descartado…")
        self.status_badge.setText("Cancelando")
        self.status_badge.set_level("warning")
        try:
            self._worker.cancel()
        except RuntimeError:
            pass
        self.warn("Cancelamento solicitado",
                  "A coleta em andamento será descartada ao terminar; nada foi alterado.")

    def _set_busy_ui(self, busy: bool, status: str) -> None:
        self._busy = busy
        self.refresh_button.setEnabled(not busy)
        self.deep_checkbox.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.status_badge.setText("Analisando" if busy else "Pronto")
        self.status_badge.set_level("accent" if busy else "gray")
        self.status_label.setText(status)
        self._update_actions()

    def _on_status(self, text: str) -> None:
        self.status_label.setText(text)

    def _on_entries(self, entries) -> None:
        if not isinstance(entries, list):
            self._on_error("O núcleo retornou uma resposta inesperada ao analisar a inicialização.", "")
            return
        self._entries = entries
        self._loaded = True
        self._checked_at = time.monotonic()
        self.status_badge.setText("Atualizado")
        self.status_badge.set_level("safe")
        self.status_label.setText(f"{len(entries)} entrada(s) analisada(s).")
        self._render()
        if not entries:
            self.banner.set_message(
                "warning", "Nenhuma entrada pôde ser lida",
                "A coleta pode falhar parcialmente sem privilégios de administrador. "
                "Isso não significa que não existam mecanismos de inicialização.")
        else:
            self.banner.clear()
        self.footer_label.setText(
            f"Última análise: {format_time(datetime.now())}  •  "
            "A lista reflete o momento da coleta; use Analisar novamente após alterações externas.")

    def _on_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Análise de inicialização falhou: %s", message)
        self._busy = False
        self._show_error("Não foi possível analisar a inicialização", message)

    def _show_error(self, title: str, message: str) -> None:
        self._busy = False
        self.status_badge.setText("Falhou")
        self.status_badge.set_level("danger")
        self.status_label.setText(message)
        self.banner.set_message("danger", title, message)
        self.table.set_empty("alert", "Inicialização indisponível",
                             "Não foi possível ler as entradas de inicialização.")
        self.table.clear()
        self._update_actions()
        self.error(title, message)

    def _on_cancelled(self) -> None:
        self._busy = False
        self.status_badge.setText("Cancelado")
        self.status_badge.set_level("warning")
        self.status_label.setText("A análise foi cancelada; a lista anterior foi mantida.")
        self.banner.set_message("warning", "Análise cancelada",
                                "Nenhum resultado parcial foi aplicado e nada foi alterado.")
        self.warn("Análise cancelada", "As entradas de inicialização não foram atualizadas.")

    def _on_finished(self) -> None:
        self._busy = False
        self._worker = None
        self.cancel_button.setEnabled(False)
        self.refresh_button.setEnabled(True)
        self.deep_checkbox.setEnabled(True)
        self._update_actions()

    # ------------------------------------------------------------------ filtros
    def _search(self) -> str:
        return self.search_input.text().strip().casefold()

    def _visible_entries(self) -> list[StartupEntry]:
        text = self._search()
        kind_index = self.kind_filter.currentIndex()
        kinds = KIND_FILTERS[kind_index][1] if 0 <= kind_index < len(KIND_FILTERS) else ()
        risk_index = self.risk_filter.currentIndex()
        threshold = RISK_FILTERS[risk_index][1] if 0 <= risk_index < len(RISK_FILTERS) else 0
        out = []
        for entry in self._entries:
            if kinds and entry.kind not in kinds:
                continue
            if risk_order(entry.risk.label) < threshold:
                continue
            haystack = f"{entry.name} {entry.command} {entry.location} {entry.exe}".casefold()
            if text and text not in haystack:
                continue
            out.append(entry)
        return out

    def _render(self) -> None:
        if not isinstance(self._entries, list):
            self._entries = []
        visible = self._visible_entries()
        if self._entries and not visible:
            self.table.set_empty("info", "Nenhuma entrada para o filtro",
                                 "Ajuste a busca, o tipo ou o nível de risco.")
        elif not self._entries:
            self.table.set_empty("startup", "Nenhuma entrada analisada",
                                 "Use Analisar novamente para ler os mecanismos de inicialização.")

        rows, payloads = [], []
        for entry in visible:
            risk = entry.risk.label
            enabled = bool(entry.enabled)
            command = str(entry.command or "")
            rows.append([
                Cell("Habilitada" if enabled else "Desativada",
                     sort_key=1 if enabled else 0,
                     color="#22c55e" if enabled else "#919bb0",
                     bold=enabled),
                Cell(KIND_LABELS.get(entry.kind, entry.kind)),
                Cell(elide(entry.name or "—", 44), tooltip=entry.name),
                Cell(risk, sort_key=risk_order(risk), color=risk_color(risk), bold=True),
                Cell(elide(entry.location or "—", 60), tooltip=entry.location),
                Cell(elide(command or "—", 90), tooltip=command),
            ])
            payloads.append(entry)
        self.table.set_rows(rows, payloads)
        self._render_stats()
        self._update_actions()

    def _render_stats(self) -> None:
        entries = self._entries
        self.stat_total.set_value(str(len(entries)) if self._loaded else "—")
        self.stat_enabled.set_value(
            str(sum(1 for e in entries if e.enabled)) if self._loaded else "—")
        self.stat_high.set_value(
            str(sum(1 for e in entries if risk_order(e.risk.label) >= 3))
            if self._loaded else "—")
        self.stat_services.set_value(
            str(sum(1 for e in entries if e.kind == "service")) if self._loaded else "—")
        self.stat_drivers.set_value(
            str(sum(1 for e in entries if e.kind == "driver")) if self._loaded else "—")

    # ------------------------------------------------------------------ ações
    def _selected(self) -> StartupEntry | None:
        payload = self.table.selected_payload()
        return payload if isinstance(payload, StartupEntry) else None

    def _update_actions(self) -> None:
        entry = self._selected()
        busy = self._busy
        self.details_button.setEnabled(entry is not None)
        can_modify = entry is not None and not busy and entry.kind != "driver"
        if entry is not None and entry.kind == "driver":
            tooltip = "Drivers não podem ser desativados por esta ferramenta."
        elif busy:
            tooltip = "Aguarde a operação atual terminar."
        else:
            tooltip = "Alterar a entrada selecionada (exige confirmação)."
        self.disable_button.setToolTip(tooltip)
        self.enable_button.setToolTip(tooltip)
        if entry is None:
            self.disable_button.setEnabled(False)
            self.enable_button.setEnabled(False)
            return
        if entry.enabled:
            self.disable_button.setEnabled(can_modify)
            self.enable_button.setEnabled(False)
            self.enable_button.setToolTip("A entrada já está habilitada.")
        else:
            removable = entry.kind in REMOVED_KINDS or (
                entry.kind == "run" and not entry.extra.get("approved_key"))
            self.disable_button.setEnabled(False)
            self.enable_button.setEnabled(can_modify and not removable)
            if removable:
                self.enable_button.setToolTip(
                    "Esta entrada foi removida do Registro; restaure o backup .reg "
                    "correspondente se necessário.")

    def _show_selected(self) -> None:
        entry = self._selected()
        if entry is not None:
            self._show_entry(entry)

    def _show_entry(self, entry) -> None:
        if not isinstance(entry, StartupEntry):
            return
        evidence_lines = []
        if entry.finding is not None:
            evidence_lines = [
                f"[{int(e.weight):+d}] {e.description}"
                for e in sorted(entry.finding.evidences, key=lambda e: -int(e.weight))
            ]
        critical = StartupManager.is_critical(entry)
        fields = [
            ("Tipo", KIND_LABELS.get(entry.kind, entry.kind)),
            ("Nome", entry.name),
            ("Situação", "Habilitada" if entry.enabled else "Desativada"),
            ("Local", entry.location),
            ("Comando", entry.command),
            ("Executável", entry.exe),
            ("Alvo", entry.target),
            ("Fabricante", entry.company),
            ("Assinatura digital", entry.signature),
            ("Risco", entry.risk.label),
            ("Pontuação", entry.finding.score if entry.finding else 0),
        ]
        note = ("Item do Windows: a desativação exige uma confirmação adicional e pode "
                "afetar o sistema." if critical else
                "Indicadores heurísticos não confirmam malware. Revise o comando e o "
                "fabricante antes de desativar uma entrada legítima.")
        if entry.kind == "driver":
            note = "Drivers não podem ser desativados por esta ferramenta."
        DetailDialog(
            self,
            f"Entrada de inicialização — {entry.name}",
            "Informações coletadas pelo núcleo. Nenhuma alteração foi executada.",
            fields=fields,
            sections=[("Indicadores", evidence_lines or "Nenhum indicador relevante encontrado.")],
            note=note,
        ).exec()

    def _disable_selected(self) -> None:
        entry = self._selected()
        if entry is None or self._busy:
            return
        if entry.kind == "driver":
            self.warn("Driver protegido",
                      "Drivers não podem ser desativados por esta ferramenta.")
            return
        critical = StartupManager.is_critical(entry)
        removed = entry.kind in REMOVED_KINDS or (
            entry.kind == "run" and not entry.extra.get("approved_key"))
        message = ("A entrada será desativada de forma reversível. Nenhum arquivo será "
                   "excluído.")
        if removed:
            message = ("O valor desta entrada será removido do Registro após a criação de "
                       "um backup .reg. A reativação exigirá restaurar o backup.")
        details = (f"Tipo: {KIND_LABELS.get(entry.kind, entry.kind)}\n"
                   f"Nome: {entry.name}\nLocal: {entry.location}\n"
                   f"Comando: {entry.command}")
        if critical:
            details += ("\n\nEsta é uma entrada do Windows. Desativá-la pode afetar "
                        "componentes do sistema.")
        if not self.confirm(
            "Desativar entrada de inicialização",
            message,
            details,
            danger=True,
            confirm_text="Desativar entrada",
            require_ack=True,
            ack_text=("Entendo que esta é uma entrada do Windows e assumo o risco."
                      if critical else
                      "Entendo que a entrada deixará de iniciar com o Windows."),
        ):
            return
        try:
            manager = self.context.startup_manager()
        except Exception as exc:
            self.error("Gerenciador de inicialização indisponível", friendly_error(exc))
            return
        self._start_mutation(
            make_startup_disable_task(manager, entry, confirm_critical=critical),
            entry, "disable", removed)

    def _enable_selected(self) -> None:
        entry = self._selected()
        if entry is None or self._busy or entry.enabled:
            return
        if entry.kind in REMOVED_KINDS or (
                entry.kind == "run" and not entry.extra.get("approved_key")):
            self.warn("Reativação não disponível",
                      "Esta entrada foi removida do Registro; restaure o backup .reg "
                      "correspondente se necessário.")
            return
        critical = StartupManager.is_critical(entry)
        details = (f"Tipo: {KIND_LABELS.get(entry.kind, entry.kind)}\n"
                   f"Nome: {entry.name}\nLocal: {entry.location}\n"
                   f"Comando: {entry.command}")
        if critical:
            details += "\n\nEsta é uma entrada do Windows."
        if not self.confirm(
            "Reativar entrada de inicialização",
            "A entrada voltará a iniciar com o Windows. Confirme apenas se reconhece este "
            "programa.",
            details,
            danger=True,
            confirm_text="Reativar entrada",
            require_ack=True,
            ack_text="Entendo que este programa voltará a ser iniciado com o Windows.",
        ):
            return
        try:
            manager = self.context.startup_manager()
        except Exception as exc:
            self.error("Gerenciador de inicialização indisponível", friendly_error(exc))
            return
        self._start_mutation(
            make_startup_enable_task(manager, entry, confirm_critical=critical),
            entry, "enable", False)

    def _start_mutation(self, task, entry: StartupEntry, action: str, removed: bool) -> None:
        self._busy = True
        self._mutation = action
        self._set_busy_ui(True, f"{'Desativando' if action == 'disable' else 'Reativando'} "
                                f"{entry.name}…")
        self.cancel_button.setEnabled(False)
        self.banner.clear()
        self.tasks.start(
            task,
            on_success=lambda result: self._on_mutation_success(result, entry, removed),
            on_error=self._on_mutation_error,
            on_status=self._on_status,
            on_finished=self._on_mutation_finished,
        )

    def _on_mutation_success(self, result, entry: StartupEntry, removed: bool) -> None:
        verb = "desativada" if self._mutation == "disable" else "reativada"
        detail = ""
        if isinstance(result, dict):
            backup = result.get("backup")
            if backup:
                detail = f" Backup criado em: {backup}"
        if removed and self._mutation == "disable":
            self._entries = [e for e in self._entries if e is not entry]
            detail += " A entrada foi removida do Registro; a reativação exige o backup .reg."
        else:
            entry.enabled = self._mutation == "enable"
        self._render()
        self.banner.set_message(
            "success", f"Entrada {verb}",
            f"{entry.name} foi {verb} pelo núcleo.{detail}")
        self.success(f"Entrada {verb}", f"{entry.name}.{detail}".strip())
        self.status_badge.setText("Atualizado")
        self.status_badge.set_level("safe")
        self.status_label.setText(
            f"{entry.name} foi {verb}. Atualize a análise para reler o sistema.")

    def _on_mutation_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Alteração de inicialização falhou: %s", message)
        self.banner.set_message("danger", "A alteração não foi concluída", message)
        self.error("A alteração não foi concluída", message)

    def _on_mutation_finished(self) -> None:
        self._busy = False
        self._mutation = ""
        self.cancel_button.setEnabled(False)
        self.refresh_button.setEnabled(True)
        self.deep_checkbox.setEnabled(True)
        if self.status_badge.text() in ("Analisando", "Desativando", "Reativando"):
            self.status_badge.setText("Pronto")
            self.status_badge.set_level("gray")
        self._update_actions()
