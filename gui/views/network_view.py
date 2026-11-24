"""Tela de Rede: conexões ativas e indicadores correlacionados.

Nenhuma conexão é bloqueada automaticamente. O `NetworkAnalyzer` apenas retrata
o estado do momento e atribui indicadores heurísticos; a tela não oferece ações
destrutivas. Sem permissão de administrador o Windows pode ocultar conexões, o
que é exibido explicitamente em vez de ser tratado como "tudo limpo".
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
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.network_analyzer import Connection
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
from ..workers.network_worker import make_network_task
from .base_view import BaseView

REFRESH_TTL = 15.0
MAX_CONNECTIONS = 800
RISK_FILTERS = [("Todos os indicadores", 0), ("Médio ou superior", 2), ("Alto e crítico", 3)]


def _endpoint(address: str, port: int) -> str:
    address = str(address or "")
    if not address:
        return "—"
    if ":" in address and not address.startswith("["):
        return f"[{address}]:{port}"
    return f"{address}:{port}" if port else address


def _finding_process(finding) -> str:
    path = str(getattr(finding, "path", "") or "—")
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    return name or path


class NetworkView(BaseView):
    KEY = "network"
    TITLE = "Rede"
    SUBTITLE = "Conexões ativas e correlação com processos"

    def __init__(self, context: AppContext, parent=None):
        self._connections: list[Connection] = []
        self._findings: list = []
        self._loaded = False
        self._loading = False
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
            "Atualizar", "refresh", tooltip="Coletar novamente as conexões de rede",
            clicked=lambda: self.refresh(force=True))
        self.processes_button = make_button(
            "Ver processos", "process", tooltip="Abrir a tela de Processos",
            clicked=lambda: self._navigate("processes"))
        self.body.addWidget(PageHeader(
            self.TITLE, self.SUBTITLE, [self.refresh_button, self.processes_button]))

        self.banner = InfoBanner()
        self.body.addWidget(self.banner)

        status_card = Card(padding=16, spacing=10)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.status_badge = Badge("Aguardando", "gray")
        self.status_label = QLabel("As conexões ainda não foram coletadas.")
        set_role(self.status_label, "muted")
        self.status_label.setWordWrap(True)
        top.addWidget(self.status_badge)
        top.addWidget(self.status_label, 1)
        status_card.body.addLayout(top)

        stats = QHBoxLayout()
        stats.setSpacing(28)
        self.stat_total = MiniStat("Conexões", "—")
        self.stat_external = MiniStat("Externas", "—")
        self.stat_established = MiniStat("Estabelecidas", "—")
        self.stat_processes = MiniStat("Processos", "—")
        self.stat_findings = MiniStat("Indicadores", "—")
        for widget in (self.stat_total, self.stat_external, self.stat_established,
                       self.stat_processes, self.stat_findings):
            stats.addWidget(widget)
        stats.addStretch(1)
        status_card.body.addLayout(stats)
        self.body.addWidget(status_card)

        # ------------------------------------------------------------ filtros
        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filtrar por processo, endereço ou estado…")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._render)
        self.external_check = QCheckBox("Somente conexões externas")
        self.external_check.setToolTip(
            "Mostrar apenas destinos roteáveis na Internet pública; redes locais e "
            "loopback são ocultados.")
        self.external_check.toggled.connect(self._render)
        self.risk_filter = QComboBox()
        for label, _level in RISK_FILTERS:
            self.risk_filter.addItem(label)
        self.risk_filter.currentIndexChanged.connect(self._render)
        filters.addWidget(self.search_input, 1)
        filters.addWidget(self.external_check, 0)
        filters.addWidget(self.risk_filter, 0)
        self.body.addLayout(filters)

        self.tabs = QTabWidget()
        self.tabs.setMinimumHeight(430)

        connections_card = Card(padding=14, spacing=10)
        self.connection_table = DataTable(
            ["Processo", "PID", "Proto", "Local", "Remoto", "Estado", "Externa"],
            empty_icon="network",
            empty_title="Nenhuma conexão visível",
            empty_text="O Windows pode ocultar conexões sem privilégios de administrador. "
                       "Isso não significa que o computador esteja sem conexões.",
        )
        self.connection_table.row_activated.connect(self._show_connection)
        self.connection_table.set_column_widths([160, 70, 70, 200, 210, 120, 80])
        self.connection_table.table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch)
        connections_card.body.addWidget(self.connection_table)
        self.tabs.addTab(connections_card, "Conexões")

        findings_card = Card(padding=14, spacing=10)
        self.finding_table = DataTable(
            ["Risco", "Processo", "Categoria", "Pontuação", "Indicadores"],
            empty_icon="check",
            empty_title="Nenhum indicador de rede",
            empty_text="Conexões externas comuns não são classificadas como ameaça; "
                       "indicadores aparecem apenas quando há evidências.",
        )
        self.finding_table.row_activated.connect(self._show_finding)
        self.finding_table.set_column_widths([85, 180, 170, 90, 320])
        self.finding_table.table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch)
        findings_card.body.addWidget(self.finding_table)
        self.tabs.addTab(findings_card, "Indicadores")
        self.body.addWidget(self.tabs)

        note = QLabel("Nenhuma conexão é bloqueada automaticamente. Os indicadores são "
                      "heurísticos e podem ter falsos positivos (jogos, P2P, atualizadores e "
                      "VPNs usam portas incomuns). Use os detalhes para correlacionar com os "
                      "processos antes de qualquer ação.")
        set_role(note, "muted2")
        note.setWordWrap(True)
        self.body.addWidget(note)

        self.footer_label = QLabel("")
        set_role(self.footer_label, "muted2")
        self.footer_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.body.addWidget(self.footer_label)
        self.body.addStretch(1)

        root.addWidget(make_scroll(content))

    # ------------------------------------------------------------------ dados
    def on_activate(self) -> None:
        super().on_activate()
        stale = not self._checked_at or (time.monotonic() - self._checked_at) >= REFRESH_TTL
        if not self._loaded or stale:
            self.refresh(force=False)

    def refresh(self, force: bool = True) -> None:
        if self._loading:
            return
        if not force and self._checked_at and \
                (time.monotonic() - self._checked_at) < REFRESH_TTL:
            return
        try:
            analyzer = self.context.network_analyzer()
        except Exception as exc:
            self._show_error("Analisador de rede indisponível", friendly_error(exc))
            return
        self._loading = True
        self._set_busy_ui(True, "Coletando conexões…")
        self.tasks.start(
            make_network_task(analyzer),
            on_success=self._on_data,
            on_error=self._on_error,
            on_status=self._on_status,
            on_cancelled=self._on_cancelled,
            on_finished=self._on_finished,
        )

    def _set_busy_ui(self, busy: bool, status: str) -> None:
        self.refresh_button.setEnabled(not busy)
        self.status_badge.setText("Coletando" if busy else "Pronto")
        self.status_badge.set_level("accent" if busy else "gray")
        self.status_label.setText(status)

    def _on_status(self, text: str) -> None:
        self.status_label.setText(text)

    def _on_data(self, result) -> None:
        connections = findings = None
        if isinstance(result, (tuple, list)) and len(result) == 2:
            connections, findings = result
        if not isinstance(connections, list) or not isinstance(findings, list):
            self._on_error("O núcleo retornou uma resposta inesperada ao analisar a rede.", "")
            return
        self._connections = connections
        self._findings = findings
        self._loaded = True
        self._checked_at = time.monotonic()
        self.status_badge.setText("Atualizado")
        self.status_badge.set_level("safe")
        self.status_label.setText(
            f"{len(connections)} conexão(ões) e {len(findings)} indicador(es) avaliados.")
        self._render()
        self._render_banner()
        if not connections:
            self.banner.set_message(
                "warning", "Nenhuma conexão pôde ser lida",
                "O Windows pode negar acesso à lista de conexões sem privilégios de "
                "administrador. A ausência de dados não confirma que não há conexões.")
        self.footer_label.setText(
            f"Última atualização: {format_time(datetime.now())}  •  "
            "Retrato do momento; conexões podem aparecer e desaparecer entre atualizações.")

    def _on_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Análise de rede falhou: %s", message)
        self._loading = False
        self._show_error("Não foi possível analisar a rede", message)

    def _show_error(self, title: str, message: str) -> None:
        self.status_badge.setText("Falhou")
        self.status_badge.set_level("danger")
        self.status_label.setText(message)
        self.banner.set_message("danger", title, message)
        self.connection_table.set_empty("alert", "Rede indisponível",
                                        "Não foi possível coletar as conexões.")
        self.connection_table.clear()
        self.finding_table.set_empty("alert", "Indicadores indisponíveis",
                                     "Não foi possível analisar as conexões.")
        self.finding_table.clear()
        self._render_stats()
        self.error(title, message)

    def _on_cancelled(self) -> None:
        self.status_badge.setText("Cancelado")
        self.status_badge.set_level("warning")
        self.status_label.setText("A coleta foi cancelada; os dados anteriores foram mantidos.")
        self.banner.set_message("warning", "Coleta cancelada",
                                "Nenhum resultado parcial foi aplicado.")
        self.warn("Coleta cancelada", "As conexões não foram atualizadas.")

    def _on_finished(self) -> None:
        self._loading = False

    # ------------------------------------------------------------------ filtros
    def _search(self) -> str:
        return self.search_input.text().strip().casefold()

    def _render(self) -> None:
        self._render_connections()
        self._render_findings()
        self._render_stats()

    def _render_connections(self) -> None:
        text = self._search()
        external_only = self.external_check.isChecked()
        rows, payloads = [], []
        for conn in self._connections[:MAX_CONNECTIONS]:
            if external_only and not conn.external:
                continue
            haystack = (f"{conn.process} {conn.exe} {conn.laddr} {conn.raddr} "
                        f"{conn.status} {conn.pid}").casefold()
            if text and text not in haystack:
                continue
            rows.append([
                Cell(elide(conn.process or "—", 34), tooltip=conn.exe or conn.process),
                Cell(str(conn.pid), sort_key=int(conn.pid)),
                Cell(str(conn.proto or "—")),
                Cell(_endpoint(conn.laddr, conn.lport)),
                Cell(_endpoint(conn.raddr, conn.rport), tooltip=conn.host),
                Cell(str(conn.status or "—")),
                Cell("Sim" if conn.external else "Não",
                     sort_key=1 if conn.external else 0,
                     color="#38bdf8" if conn.external else None,
                     bold=conn.external),
            ])
            payloads.append(conn)
        self.connection_table.set_rows(rows, payloads)

    def _findings_threshold(self) -> int:
        index = self.risk_filter.currentIndex()
        return RISK_FILTERS[index][1] if 0 <= index < len(RISK_FILTERS) else 0

    def _render_findings(self) -> None:
        text = self._search()
        threshold = self._findings_threshold()
        rows, payloads = [], []
        for finding in self._findings:
            risk = finding.risk.label
            if risk_order(risk) < threshold:
                continue
            process = _finding_process(finding)
            evidence = ""
            if finding.evidences:
                evidence = max(finding.evidences, key=lambda e: int(e.weight)).description
            haystack = f"{process} {finding.path} {finding.category} {evidence}".casefold()
            if text and text not in haystack:
                continue
            rows.append([
                Cell(risk, sort_key=risk_order(risk), color=risk_color(risk), bold=True),
                Cell(elide(process, 44), tooltip=finding.path),
                Cell(str(finding.category or "Indefinido")),
                Cell(str(finding.score or 0), sort_key=int(finding.score or 0)),
                Cell(elide(evidence or "—", 90), tooltip=evidence),
            ])
            payloads.append(finding)
        self.finding_table.set_rows(rows, payloads)

    def _render_stats(self) -> None:
        conns = self._connections
        findings = self._findings
        self.stat_total.set_value(str(len(conns)) if self._loaded else "—")
        self.stat_external.set_value(
            str(sum(1 for c in conns if c.external)) if self._loaded else "—")
        self.stat_established.set_value(
            str(sum(1 for c in conns if c.status == "ESTABLISHED")) if self._loaded else "—")
        self.stat_processes.set_value(str(len({c.pid for c in conns})) if self._loaded else "—")
        self.stat_findings.set_value(str(len(findings)) if self._loaded else "—")

    def _render_banner(self) -> None:
        if not self._findings:
            self.banner.clear()
            return
        levels = [risk_order(f.risk.label) for f in self._findings]
        worst = max(levels) if levels else 0
        if worst >= 3:
            self.banner.set_message(
                "danger", "Conexões externas com indicadores fortes",
                "Revise a aba Indicadores e correlacione com os processos. Nenhuma conexão "
                "foi bloqueada automaticamente.")
        elif worst >= 2:
            self.banner.set_message(
                "warning", "Indicadores de rede encontrados",
                "Os indícios são heurísticos e podem ter causas legítimas. Nenhuma conexão "
                "foi bloqueada automaticamente.")
        else:
            self.banner.clear()

    # ------------------------------------------------------------------ detalhes
    def _show_connection(self, conn) -> None:
        if not isinstance(conn, Connection):
            return
        DetailDialog(
            self,
            f"Conexão de {conn.process or 'processo desconhecido'}",
            "Retrato do momento da coleta. Nenhuma conexão foi alterada.",
            fields=[
                ("Processo", conn.process),
                ("PID", conn.pid),
                ("Executável", conn.exe),
                ("Protocolo", conn.proto),
                ("Endereço local", _endpoint(conn.laddr, conn.lport)),
                ("Endereço remoto", _endpoint(conn.raddr, conn.rport)),
                ("Estado", conn.status),
                ("Destino externo", "Sim" if conn.external else "Não"),
                ("Host de pool conhecido", conn.host or "—"),
            ],
            note="Endereços locais e loopback não geram tráfego externo. Nenhuma conexão "
                 "é bloqueada pelo Sentinel.",
        ).exec()

    def _show_finding(self, finding) -> None:
        if not isinstance(finding, dict) and not hasattr(finding, "risk"):
            return
        evidence_lines = [
            f"[{int(e.weight):+d}] {e.description}"
            for e in sorted(getattr(finding, "evidences", []), key=lambda e: -int(e.weight))
        ]
        extra = getattr(finding, "extra", {}) or {}
        pids = ", ".join(str(p) for p in extra.get("pids", [])) or "—"
        connection_lines = []
        for conn in extra.get("connections", []) or []:
            if not isinstance(conn, dict):
                continue
            connection_lines.append(
                f"{_endpoint(conn.get('raddr', ''), conn.get('rport', 0))} • "
                f"{conn.get('proto', '')} • {conn.get('status', '')}")
        DetailDialog(
            self,
            "Indicador de rede",
            f"Processo: {_finding_process(finding)}",
            fields=[
                ("Caminho", getattr(finding, "path", "")),
                ("Risco", finding.risk.label),
                ("Pontuação", getattr(finding, "score", 0)),
                ("Categoria", getattr(finding, "category", "")),
                ("PIDs", pids),
                ("Conexões externas", extra.get("external_count", len(connection_lines))),
            ],
            sections=[
                ("Indicadores", evidence_lines or "Nenhum indicador detalhado."),
                ("Conexões externas", connection_lines or "Nenhuma conexão externa registrada."),
            ],
            note="Indicadores são heurísticos e não confirmam atividade maliciosa. "
                 "Nenhuma conexão é bloqueada automaticamente.",
        ).exec()

    def _navigate(self, key: str) -> None:
        navigate = getattr(self.window(), "navigate", None)
        if callable(navigate):
            navigate(key)
