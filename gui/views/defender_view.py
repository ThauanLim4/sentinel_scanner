"""Tela do Microsoft Defender: estado real, definições, verificações e consultas.

A interface apenas consulta o Defender e executa ações permitidas pelo núcleo:
atualizar definições e iniciar verificações rápida/completa. Nunca desativa
proteções, nunca cria/remove exclusões e não interpreta listas vazias como
" sistema limpo". Resultados de operações são exibidos somente após a resposta
real do ``core/defender.py``.
"""
from __future__ import annotations

import time

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QProgressBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..components.common import (
    Badge,
    Card,
    FieldRow,
    InfoBanner,
    MiniStat,
    PageHeader,
    SectionHeader,
    elide,
    make_button,
    make_scroll,
    set_role,
)
from ..components.data_table import Cell, DataTable
from ..context import AppContext
from ..errors import friendly_error
from ..formatting import format_datetime
from ..workers.defender_worker import (
    SCAN_LABELS,
    make_defender_query_task,
    make_defender_scan_task,
    make_defender_status_task,
    make_defender_update_task,
)
from .base_view import BaseView


def _tri(value, *, unknown: str = "Não informado") -> tuple[str, str]:
    """Diferencia 'false' de ausência de informação (não inventa proteção)."""
    if value is None:
        return unknown, "gray"
    return ("Sim", "safe") if bool(value) else ("Não", "danger")


def _resources(value) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item)
    return str(value or "")


class DefenderView(BaseView):
    KEY = "defender"
    TITLE = "Windows Defender"
    SUBTITLE = "Estado, definições e histórico do Microsoft Defender"

    def __init__(self, context: AppContext, parent=None):
        self._status: dict | None = None
        self._threats: list = []
        self._history: list = []
        self._exclusions: dict | None = None
        self._loaded_status = False
        self._loaded_results = False
        self._busy = False
        self._worker = None
        self._worker_kind = ""
        self._checked_at = 0.0
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
            "Consultar estado", "refresh", tooltip="Reler o estado real do Defender",
            clicked=lambda: self.refresh(force=True))
        self.update_button = make_button(
            "Atualizar definições", "shield", tooltip="Executar Update-MpSignature pelo núcleo",
            clicked=self.update_signatures)
        self.quick_button = make_button(
            "Verificação rápida", "scanner", tooltip="Iniciar Start-MpScan -ScanType QuickScan",
            clicked=lambda: self.start_scan("quick"))
        self.full_button = make_button(
            "Verificação completa", "scanner", tooltip="Iniciar Start-MpScan -ScanType FullScan",
            clicked=lambda: self.start_scan("full"))
        body.addWidget(PageHeader(
            self.TITLE, self.SUBTITLE,
            [self.refresh_button, self.update_button, self.quick_button, self.full_button]))

        self.banner = InfoBanner()
        body.addWidget(self.banner)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        self.progress.setToolTip("Operação em andamento; o progresso interno do Defender não é exposto.")
        body.addWidget(self.progress)

        status_row = QHBoxLayout()
        status_row.setSpacing(10)
        self.status_badge = Badge("Aguardando", "gray")
        self.status_label = QLabel("O estado do Defender ainda não foi consultado.")
        set_role(self.status_label, "muted")
        self.status_label.setWordWrap(True)
        self.cancel_button = make_button(
            "Cancelar consulta", "stop", tooltip="Solicitar cancelamento da operação atual",
            clicked=self.cancel)
        self.cancel_button.setEnabled(False)
        status_row.addWidget(self.status_badge)
        status_row.addWidget(self.status_label, 1)
        status_row.addWidget(self.cancel_button)
        body.addLayout(status_row)

        tabs = QTabWidget()
        tabs.setObjectName("DefenderTabs")
        tabs.addTab(self._build_status_tab(), "Estado")
        tabs.addTab(self._build_threats_tab(), "Ameaças")
        tabs.addTab(self._build_history_tab(), "Histórico de detecções")
        tabs.addTab(self._build_exclusions_tab(), "Exclusões")
        body.addWidget(tabs, 1)

        note = QLabel(
            "O Sentinel nunca desativa o Defender, a proteção em tempo real ou a proteção "
            "contra adulteração, e não cria nem remove exclusões. Exclusões e ameaças são "
            "somente leitura. Uma lista vazia ou uma resposta ausente NÃO comprova que o "
            "sistema está limpo ou protegido.")
        set_role(note, "muted2")
        note.setWordWrap(True)
        body.addWidget(note)

        root.addWidget(make_scroll(content))

    def _build_status_tab(self) -> QWidget:
        widget = QWidget()
        widget.setObjectName("ViewRoot")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        card = Card(padding=16, spacing=10)
        badges = QHBoxLayout()
        badges.setSpacing(8)
        self.available_badge = Badge("Disponibilidade: —", "gray")
        self.antivirus_badge = Badge("Antivírus: —", "gray")
        self.realtime_badge = Badge("Tempo real: —", "gray")
        self.tamper_badge = Badge("Adulteração: —", "gray")
        for badge in (self.available_badge, self.antivirus_badge,
                      self.realtime_badge, self.tamper_badge):
            badges.addWidget(badge)
        badges.addStretch(1)
        card.body.addLayout(badges)

        stats = QHBoxLayout()
        stats.setSpacing(28)
        self.stat_age = MiniStat("Idade das definições", "—")
        self.stat_quick = MiniStat("Última verificação rápida", "—")
        self.stat_full = MiniStat("Última verificação completa", "—")
        for stat in (self.stat_age, self.stat_quick, self.stat_full):
            stats.addWidget(stat)
        stats.addStretch(1)
        card.body.addLayout(stats)

        self.signature_row = FieldRow("Definições", "—")
        self.products_row = FieldRow("Outros produtos", "—")
        self.message_row = FieldRow("Mensagem do núcleo", "—")
        for row in (self.signature_row, self.products_row, self.message_row):
            card.body.addWidget(row)
        layout.addWidget(card)

        results_card = Card(padding=16, spacing=10)
        results_card.body.addWidget(SectionHeader(
            "Resultados das verificações",
            trailing=make_button("Consultar resultados", "eye", clicked=self.load_results)))
        hint = QLabel(
            "Os dados abaixo vêm de Get-MpThreat e Get-MpThreatDetection. "
            "A consulta é somente leitura e falhas parciais são exibidas separadamente.")
        set_role(hint, "muted2")
        hint.setWordWrap(True)
        results_card.body.addWidget(hint)
        layout.addWidget(results_card)
        layout.addStretch(1)
        return widget

    def _build_threats_tab(self) -> QWidget:
        widget = QWidget()
        widget.setObjectName("ViewRoot")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        self.threats_banner = InfoBanner()
        layout.addWidget(self.threats_banner)
        self.threats_table = DataTable(
            ["ID", "Ameaça", "Severidade", "Ativa", "Recursos"],
            empty_icon="shield", empty_title="Nenhuma ameaça retornada",
            empty_text="Consulte os resultados. Uma lista vazia não comprova sistema limpo.")
        self.threats_table.set_column_widths([80, 190, 90, 80, 270])
        self.threats_table.row_activated.connect(self._show_threat)
        layout.addWidget(self.threats_table, 1)
        return widget

    def _build_history_tab(self) -> QWidget:
        widget = QWidget()
        widget.setObjectName("ViewRoot")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        self.history_banner = InfoBanner()
        layout.addWidget(self.history_banner)
        self.history_table = DataTable(
            ["Detectado em", "ID", "Processo", "Ação concluída", "Recursos"],
            empty_icon="shield", empty_title="Nenhum evento retornado",
            empty_text="Consulte os resultados. Ausência de eventos não é veredito de limpeza.")
        self.history_table.set_column_widths([145, 80, 180, 120, 270])
        self.history_table.row_activated.connect(self._show_history)
        layout.addWidget(self.history_table, 1)
        return widget

    def _build_exclusions_tab(self) -> QWidget:
        widget = QWidget()
        widget.setObjectName("ViewRoot")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        self.exclusions_banner = InfoBanner()
        layout.addWidget(self.exclusions_banner)
        self.exclusions_button = make_button(
            "Consultar exclusões", "eye", clicked=self.load_exclusions,
            tooltip="Ler exclusões sem alterá-las")
        hint = QLabel("Listas obtidas por Get-MpPreference. Este painel é somente leitura.")
        set_role(hint, "muted2")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        layout.addWidget(self.exclusions_button)
        card = Card(padding=16, spacing=8)
        self.paths_list = QListWidget()
        self.processes_list = QListWidget()
        self.extensions_list = QListWidget()
        for title, listing in (("Caminhos", self.paths_list),
                               ("Processos", self.processes_list),
                               ("Extensões", self.extensions_list)):
            card.body.addWidget(SectionHeader(title))
            listing.setAlternatingRowColors(True)
            listing.setMinimumHeight(80)
            card.body.addWidget(listing)
        layout.addWidget(card, 1)
        note = QLabel("Sem privilégio, o Windows pode responder 'N/A'; nesse caso as listas "
                      "são consideradas restritas, e não vazias.")
        set_role(note, "muted2")
        note.setWordWrap(True)
        layout.addWidget(note)
        return widget

    # ------------------------------------------------------------------ consulta
    def on_activate(self) -> None:
        super().on_activate()
        stale = not self._checked_at or (time.monotonic() - self._checked_at) >= 120
        if not self._loaded_status or stale:
            self.refresh(force=False)

    def refresh(self, force: bool = True) -> None:
        if self._busy:
            return
        if not force and self._checked_at and (time.monotonic() - self._checked_at) < 30:
            return
        self._start(make_defender_status_task(self.context.defender_client()), "status")

    def update_signatures(self) -> None:
        if self._busy:
            return
        self._start(make_defender_update_task(
            self.context.defender_client(), self.context.db), "update")

    def start_scan(self, kind: str) -> None:
        if self._busy or kind not in SCAN_LABELS:
            return
        self._start(make_defender_scan_task(
            self.context.defender_client(), kind, self.context.db), f"scan_{kind}")

    def load_results(self) -> None:
        if self._busy:
            return
        self._start(make_defender_query_task(
            self.context.defender_client(), "results"), "results")

    def load_exclusions(self) -> None:
        if self._busy:
            return
        self._start(make_defender_query_task(
            self.context.defender_client(), "exclusions"), "exclusions")

    def cancel(self) -> None:
        if not self._busy or self._worker is None:
            return
        self.cancel_button.setEnabled(False)
        self.status_label.setText("Cancelamento solicitado…")
        try:
            self._worker.cancel()
        except RuntimeError:
            pass

    def _start(self, task, kind: str) -> None:
        self._busy = True
        self._worker_kind = kind
        scanning = kind.startswith("scan_")
        self.cancel_button.setEnabled(True)
        self.progress.setVisible(scanning)
        self.status_badge.setText("Executando" if kind != "status" else "Consultando")
        self.status_badge.set_level("accent")
        self.status_label.setText(
            f"Verificação {SCAN_LABELS.get(kind[5:], '')} em andamento…" if scanning
            else "Aguardando a resposta real do Defender…")
        try:
            self._worker = self.tasks.start(
                task,
                on_success=self._on_success,
                on_error=self._on_error,
                on_status=self._on_status,
                on_progress=self._on_progress,
                on_cancelled=self._on_cancelled,
                on_finished=self._on_finished,
            )
        except Exception as exc:
            self._busy = False
            self._worker_kind = ""
            self._show_error("Não foi possível iniciar a operação", friendly_error(exc))

    def _on_status(self, text: str) -> None:
        self.status_label.setText(text)

    def _on_progress(self, value) -> None:
        # O Defender não expõe percentual: apenas sinaliza que está em andamento.
        self.progress.setVisible(True)

    def _on_success(self, result) -> None:
        kind = self._worker_kind
        if kind == "status":
            if not isinstance(result, dict):
                self._on_error("O núcleo retornou uma resposta inesperada ao consultar o Defender.", "")
                return
            self._status = result
            self._loaded_status = True
            self._checked_at = time.monotonic()
            self._render_status()
            return
        if kind in ("results", "threats", "history", "exclusions"):
            self._render_query(kind, result)
            return
        if kind == "update":
            if not isinstance(result, dict):
                self._on_error("O núcleo não confirmou o resultado da atualização.", "")
                return
            ok = bool(result.get("ok"))
            self.status_badge.setText("Concluído" if ok else "Não confirmado")
            self.status_badge.set_level("safe" if ok else "danger")
            if ok:
                self.status_label.setText("O Defender confirmou a atualização das definições.")
                self.banner.set_message("success", "Definições atualizadas",
                                        "Sucesso confirmado pelo cmdlet Update-MpSignature.")
            else:
                self.status_label.setText("A atualização das definições não foi confirmada.")
                self.banner.set_message("danger", "Atualização não confirmada",
                                        "Não afirmar que as definições estão atualizadas.")
            self._log_warning(result)
            return
        if kind.startswith("scan_"):
            self._render_scan_result(kind[5:], result)
            return

    def _render_status(self) -> None:
        status = self._status or {}
        self.available_badge.setText("Disponibilidade: " + _tri(status.get("available"))[0])
        self.available_badge.set_level(_tri(status.get("available"))[1])
        for key, badge in (("AntivirusEnabled", self.antivirus_badge),
                           ("RealTime", self.realtime_badge),
                           ("TamperProtected", self.tamper_badge)):
            label, level = _tri(status.get(key))
            badge.setText(f"{badge.text().split(':')[0]}: {label}")
            badge.set_level(level)

        age = status.get("SignatureAgeDays")
        self.stat_age.set_value(f"{int(age)} dia(s)" if isinstance(age, int) else "—")
        self.stat_quick.set_value(format_datetime(status.get("QuickScanEnd")))
        self.stat_full.set_value(format_datetime(status.get("FullScanEnd")))
        version = str(status.get("SignatureVersion") or "—")
        updated = format_datetime(status.get("SignatureUpdated"))
        self.signature_row.set_value(f"{version} (atualizada em {updated})")

        products = status.get("products")
        if isinstance(products, list) and products:
            self.products_row.set_value(", ".join(str(p) for p in products))
        elif isinstance(products, list):
            self.products_row.set_value(
                "Nenhum produto informado pelo Security Center (não comprova ausência).")
        else:
            self.products_row.set_value("—")
        message = str(status.get("message") or "")
        self.message_row.set_value(message or "Nenhuma mensagem adicional do núcleo.")

        protected = all(status.get(k) is True for k in
                        ("available", "AntivirusEnabled", "RealTime", "TamperProtected"))
        if message:
            level = "success" if protected else (
                "danger" if status.get("AntivirusEnabled") is False or
                status.get("RealTime") is False or status.get("available") is False
                else "warning")
            self.banner.set_message(level, "Estado informado pelo Defender", message)
        elif protected:
            self.banner.set_message("success", "Proteção ativa informada",
                                    "Estado confirmado pelo próprio Defender.")
        else:
            self.banner.set_message("warning", "Estado parcialmente informado",
                                    "Nem todas as proteções puderam ser confirmadas; "
                                    "consulte os campos acima.")
        self.status_badge.setText("Atualizado")
        self.status_badge.set_level("safe" if protected else "warning")
        self.status_label.setText("Estado consultado; nenhuma configuração foi alterada.")

    def _render_scan_result(self, kind: str, result) -> None:
        label = SCAN_LABELS.get(kind, kind)
        if not isinstance(result, dict):
            self._on_error(f"O núcleo não confirmou o resultado da verificação {label}.", "")
            return
        ok = bool(result.get("ok"))
        code = result.get("returncode")
        output = str(result.get("output") or "")
        self.status_badge.setText("Concluída" if ok else "Falhou")
        self.status_badge.set_level("safe" if ok else "danger")
        if ok:
            self.status_label.setText(
                f"Verificação {label} concluída (código {code}). Consulte os resultados.")
            self.banner.set_message(
                "success", f"Verificação {label} concluída",
                "O comando terminou com código 0. Isso NÃO é um veredito de ausência de ameaças.")
        else:
            self.status_label.setText(
                f"Verificação {label} não concluída (código {code}).")
            self.banner.set_message("danger", f"Falha na verificação {label}",
                                    output or "O Defender não confirmou o sucesso da operação.")
        self._log_warning(result)

    def _log_warning(self, result: dict) -> None:
        error = str(result.get("log_error") or "")
        if error:
            self.warn("Histórico incompleto", error)

    def _render_query(self, kind: str, result) -> None:
        if kind == "exclusions":
            if not isinstance(result, dict):
                self._on_error("O núcleo retornou exclusões em formato inesperado.", "")
                return
            self._exclusions = result
            self._render_exclusions()
            return
        if kind == "results":
            if not isinstance(result, dict) or not isinstance(result.get("threats"), list) \
                    or not isinstance(result.get("history"), list):
                self._on_error("O núcleo retornou resultados em formato inesperado.", "")
                return
            self._threats = result["threats"]
            self._history = result["history"]
            self._loaded_results = True
            self._render_threats()
            self._render_history()
            self.status_badge.setText("Atualizado")
            self.status_badge.set_level("safe")
            self.status_label.setText(
                f"{len(self._threats)} ameaça(s) e {len(self._history)} evento(s) retornados.")
            self.banner.set_message("info", "Resultados consultados",
                                    "Listas vazias indicam apenas ausência de dados na resposta, "
                                    "não comprova sistema limpo.")
            return

    def _render_threats(self) -> None:
        rows, payloads = [], []
        for threat in self._threats if isinstance(self._threats, list) else []:
            if not isinstance(threat, dict):
                continue
            active, level = _tri(threat.get("IsActive"), unknown="—")
            rows.append([
                Cell(str(threat.get("ThreatID") or "—")),
                Cell(elide(str(threat.get("ThreatName") or "—"), 40),
                     tooltip=str(threat.get("ThreatName") or "")),
                Cell(str(threat.get("SeverityID") or "—")),
                Cell(active, color={"safe": "#f59e0b", "danger": "#ef4444",
                                    "gray": "#919bb0"}[level]),
                Cell(elide(_resources(threat.get("Resources")), 60),
                     tooltip=_resources(threat.get("Resources"))),
            ])
            payloads.append(threat)
        self.threats_table.set_rows(rows, payloads)
        if not rows:
            self.threats_banner.set_message(
                "warning", "Nenhuma ameaça retornada",
                "Get-MpThreat não devolveu registros; isso não comprova ausência de ameaças.")
        else:
            self.threats_banner.clear()

    def _render_history(self) -> None:
        rows, payloads = [], []
        for event in self._history if isinstance(self._history, list) else []:
            if not isinstance(event, dict):
                continue
            action, level = _tri(event.get("ActionSuccess"), unknown="—")
            rows.append([
                Cell(format_datetime(event.get("Time")),
                     sort_key=str(event.get("Time") or "")),
                Cell(str(event.get("ThreatID") or "—")),
                Cell(elide(str(event.get("ProcessName") or "—"), 35),
                     tooltip=str(event.get("ProcessName") or "")),
                Cell(action, color={"safe": "#22c55e", "danger": "#ef4444",
                                    "gray": "#919bb0"}[level]),
                Cell(elide(_resources(event.get("Resources")), 60),
                     tooltip=_resources(event.get("Resources"))),
            ])
            payloads.append(event)
        self.history_table.set_rows(rows, payloads)
        if not rows:
            self.history_banner.set_message(
                "warning", "Nenhum evento retornado",
                "Get-MpThreatDetection não devolveu eventos; isso não comprova sistema limpo.")
        else:
            self.history_banner.clear()

    def _render_exclusions(self) -> None:
        data = self._exclusions or {}
        restricted = bool(data.get("restricted"))
        for key, widget in (("Paths", self.paths_list), ("Processes", self.processes_list),
                            ("Extensions", self.extensions_list)):
            widget.clear()
            for item in data.get(key) or []:
                widget.addItem(str(item))
        if restricted:
            self.exclusions_banner.set_message(
                "warning", "Exclusões com acesso restrito",
                "O Windows não forneceu as listas sem privilégios adequados. "
                "As listas vazias não significam que não existem exclusões.")
        else:
            self.exclusions_banner.set_message(
                "info", "Exclusões somente leitura",
                "As listas refletem o momento da consulta; este painel não altera o Defender.")
        self.status_badge.setText("Atualizado")
        self.status_badge.set_level("warning" if restricted else "safe")
        self.status_label.setText("Exclusões consultadas; nenhuma foi criada ou removida.")

    def _on_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Operação do Defender falhou: %s", message)
        self.status_badge.setText("Falhou")
        self.status_badge.set_level("danger")
        self.status_label.setText(message)
        self.banner.set_message("danger", "Operação não confirmada", message)
        self.error("Windows Defender", message)

    def _show_error(self, title: str, message: str) -> None:
        self._on_error(message)

    def _on_cancelled(self) -> None:
        self.status_badge.setText("Cancelado")
        self.status_badge.set_level("warning")
        self.status_label.setText("Operação cancelada; nenhum resultado parcial foi aplicado.")
        note = ("A verificação pode ter sido interrompida globalmente no Defender; "
                "consulte o estado para confirmar."
                if self._worker_kind.startswith("scan_") else
                "A consulta foi descartada; os dados anteriores foram mantidos.")
        self.banner.set_message("warning", "Operação cancelada", note)
        self.warn("Defender", "Operação cancelada")

    def _on_finished(self) -> None:
        self._busy = False
        self._worker = None
        self._worker_kind = ""
        self.cancel_button.setEnabled(False)
        self.progress.setVisible(False)
        self._update_actions()

    # ------------------------------------------------------------------ detalhes
    def _update_actions(self) -> None:
        enabled = not self._busy
        for button in (self.refresh_button, self.update_button,
                       self.quick_button, self.full_button, self.exclusions_button):
            button.setEnabled(enabled)

    def _show_threat(self, payload) -> None:
        if not isinstance(payload, dict):
            return
        from ..components.detail_dialog import DetailDialog
        DetailDialog(
            self, f"Ameaça do Defender — {payload.get('ThreatName') or payload.get('ThreatID')}",
            "Dados retornados por Get-MpThreat (somente leitura).",
            fields=[("ID", str(payload.get("ThreatID") or "—")),
                    ("Nome", str(payload.get("ThreatName") or "—")),
                    ("Severidade", str(payload.get("SeverityID") or "—")),
                    ("Ativa", _tri(payload.get("IsActive"), unknown="—")[0]),
                    ("Recursos", _resources(payload.get("Resources")) or "—")],
            note="A presença de uma ameaça ativa deve ser tratada pelo próprio Defender.",
        ).exec()

    def _show_history(self, payload) -> None:
        if not isinstance(payload, dict):
            return
        from ..components.detail_dialog import DetailDialog
        DetailDialog(
            self, "Evento de detecção do Defender",
            "Dados retornados por Get-MpThreatDetection (somente leitura).",
            fields=[("Detectado em", format_datetime(payload.get("Time"))),
                    ("ID da ameaça", str(payload.get("ThreatID") or "—")),
                    ("Processo", str(payload.get("ProcessName") or "—")),
                    ("Ação concluída", _tri(payload.get("ActionSuccess"), unknown="—")[0]),
                    ("Status de execução", str(payload.get("CurrentThreatExecutionStatusID") or "—")),
                    ("Recursos", _resources(payload.get("Resources")) or "—")],
            note="O resultado da ação é o informado pelo Defender; não foi reavaliado aqui.",
        ).exec()
