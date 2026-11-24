"""Dashboard: visão geral da proteção, métricas e atividade recente.

Regras de honestidade da tela:

- "Protegido" só é exibido quando a última varredura terminou sem detecções **e**
  o Windows Defender respondeu com proteção em tempo real ativa e definições
  atualizadas. Qualquer informação ausente rebaixa o estado para "Verificando".
- Os dados locais vêm do banco; a consulta ao Defender e a contagem de processos
  rodam em threads próprias. Nenhum widget é atualizado fora da thread principal.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHeaderView, QVBoxLayout, QWidget

from ..components.common import (
    Card,
    PageHeader,
    SectionHeader,
    InfoBanner,
    card_grid,
    elide,
    make_button,
    make_scroll,
    set_role,
)
from ..components.data_table import Cell, DataTable
from ..components.detail_dialog import DetailDialog
from ..components.metric_card import metric_card
from ..components.status_card import ProtectionCard
from ..context import AppContext
from ..errors import friendly_error
from ..formatting import (
    action_label,
    format_datetime,
    format_time,
    relative_time,
    risk_color,
    risk_order,
)
from ..workers.defender_worker import make_defender_status_task
from ..workers.process_worker import make_count_task
from .base_view import BaseView

DEFENDER_TTL = 90.0
PROCESS_TTL = 20.0
MAX_ROWS = 12

SCAN_KIND_LABEL = {
    "quick": "Varredura rápida",
    "full": "Varredura completa",
    "custom": "Varredura personalizada",
    "file": "Análise de arquivo",
}

FINDING_STATUS_LABEL = {
    "open": "Aberta",
    "quarantined": "Em quarentena",
    "resolved": "Resolvida",
    "ignored": "Ignorada",
    "deleted": "Excluída",
}


@dataclass(frozen=True)
class ProtectionAssessment:
    """Resultado puro da avaliação do estado de proteção."""

    level: str
    title: str
    badge: str
    description: str
    reasons: tuple[str, ...]
    defender_text: str
    last_scan_text: str


def _kind_label(kind: str) -> str:
    return SCAN_KIND_LABEL.get(str(kind or ""), str(kind or "Varredura"))


def evaluate_protection(summary: dict | None = None, latest_findings: list | None = None,
                        defender: dict | None = None,
                        defender_error: str | None = None) -> ProtectionAssessment:
    """Avalia o estado de proteção sem tocar em widgets, banco ou rede.

    ``latest_findings`` deve ser ``None`` quando as detecções da última varredura
    não puderam ser lidas. Uma lista vazia significa "nenhuma detecção".
    """
    summary = summary or {}
    latest = summary.get("latest_scan")
    reasons: list[tuple[str, str]] = []
    unresolved = False

    # ---------------------------------------------------------------- Defender
    defender_text = "Verificando…"
    if defender_error:
        defender_text = "Indisponível"
        reasons.append(("warning", f"Não foi possível consultar o Windows Defender: {defender_error}"))
    elif defender is None:
        unresolved = True
    else:
        available = bool(defender.get("available"))
        av_enabled = defender.get("AntivirusEnabled")
        real_time = defender.get("RealTime")
        tamper = defender.get("TamperProtected")
        age = defender.get("SignatureAgeDays")
        message = str(defender.get("message") or "").strip()
        products = defender.get("products") or []
        if not available:
            defender_text = "Indisponível"
            detail = message or "O serviço do Microsoft Defender não está ativo."
            if products:
                detail += " Produtos de segurança detectados: " + ", ".join(map(str, products)) + "."
            reasons.append(("warning", detail))
        elif av_enabled is False:
            defender_text = "Antivírus desativado"
            reasons.append(("danger", "O antivírus do Microsoft Defender está desativado."))
        elif real_time is False:
            defender_text = "Tempo real desativado"
            reasons.append(("danger", "A proteção em tempo real do Windows Defender está desativada."))
        elif real_time is None:
            defender_text = "Estado desconhecido"
            reasons.append(("warning", "Não foi possível confirmar a proteção em tempo real."))
        elif age is None:
            defender_text = "Ativo (definições sem data)"
            reasons.append(("warning", "A data das definições de vírus do Defender é desconhecida."))
        else:
            try:
                age = int(age)
            except (TypeError, ValueError):
                age = None
            if age is None:
                defender_text = "Ativo (idade desconhecida)"
                reasons.append(("warning", "Não foi possível interpretar a idade das definições de vírus."))
            elif age > 14:
                defender_text = f"Definições há {age} dias"
                reasons.append(("danger", f"As definições de vírus estão muito desatualizadas ({age} dias)."))
            elif age > 3:
                defender_text = f"Ativo (definições há {age} dias)"
                reasons.append(("warning", f"As definições de vírus estão desatualizadas ({age} dias)."))
            else:
                defender_text = "Ativo e atualizado"
        if available and tamper is False:
            reasons.append(("warning", "A proteção contra adulteração do Defender está desativada."))

    # ------------------------------------------------------------------ Scans
    if latest is None:
        last_scan_text = "Nenhuma varredura"
        reasons.append(("warning", "Nenhuma varredura foi registrada neste computador."))
    else:
        last_scan_text = (f"{_kind_label(latest.get('kind'))} • "
                          f"{relative_time(latest.get('finished') or latest.get('started'))}")
        status = str(latest.get("status") or "").lower()
        if status == "running":
            reasons.append(("warning", "Há uma varredura marcada como em andamento ou interrompida."))
        elif status and status != "completed":
            reasons.append(("warning", f"A última varredura terminou com estado '{status}'."))

        summary_count = summary.get("latest_findings")
        if latest_findings is None:
            if summary_count:
                reasons.append(("warning", f"A última varredura registrou {summary_count} detecção(ões), "
                                            "mas os detalhes não estão disponíveis."))
            elif summary_count is None:
                reasons.append(("warning", "Não foi possível confirmar as detecções da última varredura."))
            findings = []
        else:
            findings = list(latest_findings)

        if findings:
            severe = [f for f in findings if risk_order(f.get("risk", "")) >= 3]
            if severe:
                reasons.append(("danger", f"A última varredura encontrou {len(severe)} detecção(ões) "
                                          "de risco alto ou crítico."))
            else:
                reasons.append(("warning", f"A última varredura encontrou {len(findings)} detecção(ões) "
                                          "de risco baixo ou médio."))
        elif latest_findings is not None and summary_count not in (None, 0) and not findings:
            reasons.append(("warning", "O resumo e os detalhes das detecções não coincidem."))

    # ------------------------------------------------------------------ Saída
    if any(level == "danger" for level, _ in reasons):
        level, title, badge = "danger", "Risco identificado", "Risco"
    elif any(level == "warning" for level, _ in reasons):
        level, title, badge = "warning", "Atenção necessária", "Atenção"
    elif unresolved:
        level, title, badge = "muted", "Verificando proteção", "Verificando"
    else:
        level, title, badge = "safe", "Sistema protegido", "Protegido"

    if level == "safe":
        description = ("Nenhuma detecção na última varredura e o Windows Defender está ativo "
                       "com proteção em tempo real e definições atualizadas.")
    elif level == "muted":
        description = ("Aguardando o estado do Windows Defender para concluir a avaliação. "
                       "O Sentinel não exibe 'protegido' sem essa confirmação.")
    else:
        description = " ".join(text for _, text in reasons[:2])

    return ProtectionAssessment(
        level=level,
        title=title,
        badge=badge,
        description=description,
        reasons=tuple(text for _, text in reasons),
        defender_text=defender_text,
        last_scan_text=last_scan_text,
    )


def _format_int(value) -> str:
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        return "—"
    return f"{number:,}".replace(",", ".")


def _status_label(status) -> str:
    key = str(status or "open").lower()
    return FINDING_STATUS_LABEL.get(key, key.replace("_", " ").title())


class DashboardView(BaseView):
    KEY = "dashboard"
    TITLE = "Dashboard"
    SUBTITLE = "Visão geral da proteção e da atividade recente"

    def __init__(self, context: AppContext, parent=None):
        self._summary: dict = {}
        self._findings: list = []
        self._actions: list = []
        self._defender: dict | None = None
        self._defender_error: str | None = None
        self._process_count: int | None = None
        self._process_error: str | None = None
        self._defender_checked_at = 0.0
        self._process_checked_at = 0.0
        self._defender_running = False
        self._process_running = False
        self._loaded = False
        self._refresh_pending = False
        self._assessment: ProtectionAssessment | None = None
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
            "Atualizar", "refresh", tooltip="Recarregar os dados locais e consultar o Defender",
            clicked=self.refresh_forced)
        self.quick_button = make_button(
            "Varredura rápida", "play", kind="primary",
            tooltip="Iniciar uma varredura rápida na tela do Scanner",
            clicked=lambda: self._start_scan("quick"))
        self.header = PageHeader(self.TITLE, self.SUBTITLE,
                                 [self.refresh_button, self.quick_button])
        self.body.addWidget(self.header)

        self.banner = InfoBanner()
        self.body.addWidget(self.banner)

        self.protection = ProtectionCard()
        self.quarantine_button = make_button(
            "Ver quarentena", "quarantine", tooltip="Abrir os itens isolados",
            clicked=lambda: self._navigate("quarantine"))
        self.history_shortcut = make_button(
            "Abrir histórico", "history", tooltip="Ver varreduras, detecções e operações",
            clicked=lambda: self._navigate("history"))
        self.protection.add_action(self.quarantine_button)
        self.protection.add_action(self.history_shortcut)
        self.body.addWidget(self.protection)

        self.metric_scans = metric_card("Varreduras", "—", "Total registrado", "scanner")
        self.metric_files = metric_card("Arquivos verificados", "—", "Somatório das varreduras", "file")
        self.metric_findings = metric_card("Detecções", "—", "Todas as varreduras", "alert", "@red")
        self.metric_quarantine = metric_card("Em quarentena", "—", "Itens isolados", "quarantine", "@accent")
        self.metric_processes = metric_card("Processos ativos", "—", "Aguardando leitura", "process", "@blue")
        self.metric_cards = [self.metric_scans, self.metric_files, self.metric_findings,
                             self.metric_quarantine, self.metric_processes]
        self.body.addWidget(card_grid(self.metric_cards, columns=5))

        self.findings_title = SectionHeader(
            "Detecções da última varredura",
            make_button("Ver histórico", "history", tooltip="Abrir o histórico completo",
                        clicked=lambda: self._navigate("history")))
        self.body.addWidget(self.findings_title)
        findings_card = Card(padding=14, spacing=0)
        self.findings_table = DataTable(
            ["Risco", "Categoria", "Caminho", "Pontuação", "Estado"],
            empty_icon="check", empty_title="Nenhuma detecção registrada",
            empty_text="Execute uma varredura para analisar o computador.",
        )
        self.findings_table.row_activated.connect(self._show_finding)
        self.findings_table.set_column_widths([85, 150, 300, 90, 120])
        findings_card.body.addWidget(self.findings_table)
        self.body.addWidget(findings_card)

        self.body.addWidget(SectionHeader("Atividade recente",
                                          make_button("Limpar notificações", "bell",
                                                      clicked=self._clear_notifications)))
        activity_card = Card(padding=14, spacing=0)
        self.activity_table = DataTable(
            ["Quando", "Ação", "Alvo", "Resultado"],
            empty_icon="history", empty_title="Nenhuma atividade registrada",
            empty_text="Quarentenas, limpezas e outras operações aparecerão aqui.",
        )
        self.activity_table.row_activated.connect(self._show_action)
        self.activity_table.set_column_widths([110, 190, 300, 110])
        activity_card.body.addWidget(self.activity_table)
        self.body.addWidget(activity_card)

        self.footer_label = make_footer_label()
        self.body.addWidget(self.footer_label)
        self.body.addStretch(1)

        scroll = make_scroll(content)
        root.addWidget(scroll)

        # A coluna de caminho/alvo absorve o espaço restante.
        self.findings_table.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self.activity_table.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)

        if self.context.db is None:
            self._show_db_error()

    # ------------------------------------------------------------------ dados
    def on_activate(self) -> None:
        super().on_activate()
        if self._refresh_pending:
            self._refresh_pending = False
            self.refresh(force=True)
        else:
            self.refresh(force=False)

    def invalidate(self) -> None:
        """Marca os dados como desatualizados após uma mudança real no banco.

        Se a tela estiver visível, recarrega imediatamente; caso contrário o
        recarregamento ocorre ao abrir o Dashboard novamente.
        """
        self._refresh_pending = True
        if self.isVisible():
            self._refresh_pending = False
            self.refresh(force=True)

    def refresh_forced(self) -> None:
        self._refresh_pending = False
        self.refresh(force=True)

    def refresh(self, force: bool = False) -> None:
        db = self.context.db
        if db is None:
            self._show_db_error()
            return
        try:
            summary = db.summary()
            latest = summary.get("latest_scan")
            findings = db.list_findings(scan_id=latest["id"]) if latest else []
            actions = db.list_actions(limit=MAX_ROWS)
        except Exception as exc:  # banco quebrado não pode derrubar a janela
            self.context.log.exception("Falha ao ler os dados do dashboard")
            self._loaded = False
            self.banner.set_message("danger", "Falha ao ler o histórico local",
                                    friendly_error(exc))
            self.findings_table.set_empty("alert", "Histórico indisponível",
                                          "Não foi possível ler o banco de dados.")
            self.findings_table.clear()
            self.activity_table.set_empty("alert", "Histórico indisponível",
                                          "Não foi possível ler o banco de dados.")
            self.activity_table.clear()
            return

        self._summary = summary
        self._findings = findings
        self._actions = actions
        self._loaded = True
        self._render_all()
        self._probe_defender(force)
        self._probe_processes(force)

    def _render_all(self) -> None:
        summary = self._summary
        self.quick_button.setEnabled(True)
        self.metric_scans.set_value(_format_int(summary.get("scans")))
        self.metric_files.set_value(_format_int(summary.get("files")))
        self.metric_findings.set_value(_format_int(summary.get("findings")))
        self.metric_quarantine.set_value(_format_int(summary.get("quarantined")))
        self._update_process_metric()
        self._render_findings()
        self._render_actions()
        self._refresh_assessment()
        self._stamp_refresh()

    def _render_findings(self) -> None:
        findings = self._findings
        latest = self._summary.get("latest_scan")
        count = len(findings)
        if latest is not None:
            self.findings_title.title_label.setText(
                f"Detecções da última varredura ({count})" if count
                else "Detecções da última varredura")
        else:
            self.findings_title.title_label.setText("Detecções recentes")
        if latest is None:
            self.findings_table.set_empty(
                "scanner", "Nenhuma varredura registrada",
                "Execute uma varredura rápida para analisar o computador.")
        elif count == 0:
            self.findings_table.set_empty(
                "check", "Nenhuma detecção na última varredura",
                "Isso não substitui a proteção em tempo real do Windows Defender.")
        else:
            self.findings_table.set_empty(
                "alert", "Detecções encontradas",
                "Abra uma linha para ver as evidências. O Scanner não remove arquivos automaticamente.")

        rows, payloads = [], []
        for finding in findings[:MAX_ROWS]:
            risk = str(finding.get("risk") or "SEGURO")
            status = finding.get("status")
            path = str(finding.get("path") or "—")
            rows.append([
                Cell(risk, sort_key=risk_order(risk), color=risk_color(risk), bold=True),
                Cell(str(finding.get("category") or "Indefinido")),
                Cell(elide(path, 72), tooltip=path),
                Cell(str(finding.get("score") or 0), sort_key=int(finding.get("score") or 0)),
                Cell(_status_label(status), color="#22c55e" if str(status or "open").lower()
                     in ("resolved", "quarantined", "deleted") else None),
            ])
            payloads.append(finding)
        self.findings_table.set_rows(rows, payloads)

    def _render_actions(self) -> None:
        rows, payloads = [], []
        for action in self._actions[:MAX_ROWS]:
            target = str(action.get("target") or "—")
            success = bool(action.get("success"))
            rows.append([
                Cell(relative_time(action.get("ts")), sort_key=str(action.get("ts") or ""),
                     tooltip=format_datetime(action.get("ts"))),
                Cell(action_label(action.get("action"))),
                Cell(elide(target, 72), tooltip=target),
                Cell("OK" if success else "Falhou", sort_key=1 if success else 0,
                     color="#22c55e" if success else "#ef4444", bold=True),
            ])
            payloads.append(action)
        self.activity_table.set_rows(rows, payloads)

    def _update_process_metric(self) -> None:
        if self._process_error:
            self.metric_processes.set_value("—")
            self.metric_processes.set_hint("Não foi possível contar")
        elif self._process_count is None:
            self.metric_processes.set_value("—")
            self.metric_processes.set_hint("Leitura em andamento…")
        else:
            self.metric_processes.set_value(_format_int(self._process_count))
            self.metric_processes.set_hint("Processos visíveis no momento")

    def _refresh_assessment(self) -> None:
        if not self._loaded:
            return
        assessment = evaluate_protection(
            self._summary, self._findings, self._defender, self._defender_error)
        self._assessment = assessment
        self.protection.set_state(assessment.level, assessment.title,
                                  assessment.description, assessment.badge)
        summary = self._summary
        latest = summary.get("latest_scan")
        threats = "—" if latest is None else str(len(self._findings))
        self.protection.set_stats([
            ("Última varredura", assessment.last_scan_text),
            ("Ameaças na última varredura", threats),
            ("Itens em quarentena", _format_int(summary.get("quarantined"))),
            ("Windows Defender", assessment.defender_text),
        ])
        self.set_system_status(assessment.badge,
                               {"safe": "safe", "warning": "warning", "danger": "danger"}
                               .get(assessment.level, "gray"))
        self._render_banner()

    def _render_banner(self) -> None:
        if not self._loaded:
            return
        if self._defender_error:
            self.banner.set_message(
                "warning", "Windows Defender indisponível",
                self._defender_error + " O estado da proteção não pode ser confirmado.")
            return
        defender = self._defender
        if defender is not None and not defender.get("available"):
            message = str(defender.get("message") or
                          "O serviço do Microsoft Defender não está ativo.")
            self.banner.set_message(
                "warning", "Windows Defender indisponível",
                message + " Nenhuma alteração foi feita nas configurações de segurança.")
            return
        if self._process_error:
            self.banner.set_message(
                "info", "Contagem de processos indisponível", self._process_error)
            return
        self.banner.clear()

    def _stamp_refresh(self) -> None:
        self.footer_label.setText(
            f"Última atualização: {format_time(datetime.now())}  •  "
            "Dados lidos do banco local do Sentinel; nenhuma alteração foi feita no sistema.")

    # ------------------------------------------------------------------ sondas
    def _probe_defender(self, force: bool) -> None:
        if self._defender_running:
            return
        now = time.monotonic()
        if not force and self._defender_checked_at and now - self._defender_checked_at < DEFENDER_TTL:
            return
        self._defender_running = True
        try:
            client = self.context.defender_client()
        except Exception as exc:
            self._defender_running = False
            self._defender_error = friendly_error(exc)
            self._refresh_assessment()
            return
        self.tasks.start(
            make_defender_status_task(client),
            on_success=self._on_defender,
            on_error=self._on_defender_error,
            on_finished=self._defender_finished,
        )

    def _probe_processes(self, force: bool) -> None:
        if self._process_running:
            return
        now = time.monotonic()
        if not force and self._process_checked_at and now - self._process_checked_at < PROCESS_TTL:
            return
        self._process_running = True
        try:
            analyzer = self.context.process_analyzer()
        except Exception as exc:
            self._process_running = False
            self._process_error = friendly_error(exc)
            self._update_process_metric()
            return
        self.tasks.start(
            make_count_task(analyzer),
            on_success=self._on_process_count,
            on_error=self._on_process_error,
            on_finished=self._process_finished,
        )

    def _on_defender(self, result) -> None:
        self._defender = result if isinstance(result, dict) else None
        self._defender_error = None
        self._defender_checked_at = time.monotonic()
        self._refresh_assessment()

    def _on_defender_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Consulta ao Defender falhou: %s", message)
        self._defender = None
        self._defender_error = message
        self._defender_checked_at = time.monotonic()
        self._refresh_assessment()

    def _defender_finished(self) -> None:
        self._defender_running = False

    def _on_process_count(self, result) -> None:
        try:
            self._process_count = int(result)
            self._process_error = None
        except (TypeError, ValueError):
            self._process_count = None
            self._process_error = "Resposta inválida ao contar processos."
        self._process_checked_at = time.monotonic()
        self._update_process_metric()
        self._render_banner()

    def _on_process_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Contagem de processos falhou: %s", message)
        self._process_count = None
        self._process_error = message
        self._process_checked_at = time.monotonic()
        self._update_process_metric()
        self._render_banner()

    def _process_finished(self) -> None:
        self._process_running = False

    # ------------------------------------------------------------------ ações
    def _navigate(self, key: str) -> None:
        window = self.window()
        navigate = getattr(window, "navigate", None)
        if callable(navigate):
            navigate(key)

    def _start_scan(self, kind: str) -> None:
        window = self.window()
        start = getattr(window, "start_scan", None)
        if callable(start):
            start(kind)
        else:
            self._navigate("scanner")

    def _clear_notifications(self) -> None:
        window = self.window()
        center = getattr(window, "notifications", None)
        if center is not None and hasattr(center, "clear"):
            center.clear()

    def _show_finding(self, finding) -> None:
        if not isinstance(finding, dict):
            return
        import json

        evidences = []
        try:
            payload = json.loads(finding.get("evidence_json") or "{}")
            evidences = payload.get("evidences") or []
        except (TypeError, ValueError):
            evidences = []
        evidence_lines = []
        for evidence in evidences:
            if not isinstance(evidence, dict):
                continue
            weight = evidence.get("weight", 0)
            description = evidence.get("description", "")
            evidence_lines.append(f"[{weight:+d}] {description}")
        fields = [
            ("Caminho", finding.get("path")),
            ("Risco", finding.get("risk")),
            ("Pontuação", finding.get("score")),
            ("Categoria", finding.get("category")),
            ("Status", _status_label(finding.get("status"))),
            ("SHA-256", finding.get("sha256")),
        ]
        DetailDialog(
            self,
            "Detecção",
            "Evidências registradas pela varredura. O arquivo não foi removido automaticamente.",
            fields=fields,
            sections=[("Evidências", evidence_lines or "Nenhuma evidência detalhada.")],
            note="Para isolar o arquivo, use a quarentena a partir do histórico (com confirmação).",
        ).exec()

    def _show_action(self, action) -> None:
        if not isinstance(action, dict):
            return
        DetailDialog(
            self,
            "Operação registrada",
            format_datetime(action.get("ts")),
            fields=[
                ("Ação", action_label(action.get("action"))),
                ("Alvo", action.get("target")),
                ("Resultado", "Concluída" if action.get("success") else "Falhou"),
                ("Detalhe", action.get("detail")),
            ],
            note="Registro de auditoria local. Nenhuma operação é executada ao abrir este detalhe.",
        ).exec()

    # ------------------------------------------------------------------ erros
    def _show_db_error(self) -> None:
        self._loaded = False
        error = self.context.db_error or "Não foi possível abrir o banco de dados."
        self.banner.set_message("danger", "Banco de dados indisponível",
                                friendly_error(error))
        self.quick_button.setEnabled(False)
        for card in self.metric_cards:
            card.set_value("—")
            card.set_hint("Indisponível")
        self.findings_table.set_empty("alert", "Histórico indisponível",
                                      "O banco de dados não pôde ser aberto.")
        self.findings_table.clear()
        self.activity_table.set_empty("alert", "Histórico indisponível",
                                      "O banco de dados não pôde ser aberto.")
        self.activity_table.clear()
        self.protection.set_state(
            "muted", "Sem dados locais",
            "O estado da proteção não pode ser confirmado sem o banco de dados.", "Indisponível")
        self.protection.set_stats([
            ("Última varredura", "—"), ("Ameaças na última varredura", "—"),
            ("Itens em quarentena", "—"), ("Windows Defender", "—"),
        ])
        self.set_system_status("Dados indisponíveis", "danger")


def make_footer_label():
    from PySide6.QtWidgets import QLabel

    label = QLabel()
    set_role(label, "muted2")
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label
