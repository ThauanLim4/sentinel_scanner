"""Tela de varredura: execução assíncrona, progresso, cancelamento e resultados.

O Scanner **não** remove arquivos automaticamente. A única ação destrutiva oferecida
é "Isolar em quarentena", sempre com confirmação explícita e executada pelo núcleo
(`core/quarantine.py`). Detecções por heurística e por hash conhecido são exibidas
com origens diferentes.
"""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from core.scanner import ScanProgress, ScanResult
from ..components.common import (
    Badge,
    Card,
    EmptyState,
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
from ..components.detail_dialog import DetailDialog
from ..context import AppContext
from ..errors import friendly_error
from ..formatting import (
    format_datetime,
    format_duration,
    risk_color,
    risk_order,
    short_hash,
)
from ..workers.quarantine_worker import make_quarantine_task
from ..workers.scan_worker import make_scan_task
from .base_view import BaseView

MAX_RESULTS = 500


def _origin(finding: dict) -> tuple[str, str]:
    """Classifica a origem da detecção sem inventar confirmação.

    Somente o hash presente na base local é tratado como assinatura confirmada.
    Assinatura Authenticode válida é apenas um redutor de falso positivo.
    """
    codes = _evidence_codes(finding)
    if "known_hash" in codes:
        return "Assinatura confirmada", "#ef4444"
    if "sig_ms" in codes or "sig_valid" in codes:
        return "Heurística (assinado)", "#38bdf8"
    return "Heurística", "#f59e0b"


def _evidence_codes(finding: dict) -> set[str]:
    try:
        payload = json.loads(finding.get("evidence_json") or "{}")
    except (TypeError, ValueError):
        return set()
    evidences = payload.get("evidences") if isinstance(payload, dict) else None
    if not isinstance(evidences, list):
        return set()
    return {str(e.get("code")) for e in evidences if isinstance(e, dict)}


def _evidence_list(finding: dict) -> list[str]:
    try:
        payload = json.loads(finding.get("evidence_json") or "{}")
    except (TypeError, ValueError):
        return []
    evidences = payload.get("evidences") if isinstance(payload, dict) else None
    lines = []
    for evidence in evidences or []:
        if not isinstance(evidence, dict):
            continue
        lines.append(f"[{int(evidence.get('weight') or 0):+d}] "
                     f"{evidence.get('description', '')}")
    return lines


class ScannerView(BaseView):
    KEY = "scanner"
    TITLE = "Scanner"
    SUBTITLE = "Análise de arquivos com progresso, cancelamento e resultados"

    def __init__(self, context: AppContext, parent=None):
        self._running = False
        self._worker = None
        self._scan_id: int | None = None
        self._findings: list = []
        self._last_result: ScanResult | None = None
        self._loaded_last = False
        self._quarantining = False
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

        self.quick_button = make_button("Varredura rápida", "play", kind="primary",
                                        tooltip="Analisar locais de risco comuns",
                                        clicked=lambda: self.begin_scan("quick"))
        self.full_button = make_button("Varredura completa", "search",
                                       tooltip="Analisar também pastas do Windows e Program Files",
                                       clicked=lambda: self.begin_scan("full"))
        self.body.addWidget(PageHeader(self.TITLE, self.SUBTITLE,
                                       [self.quick_button, self.full_button]))

        self.banner = InfoBanner()
        self.body.addWidget(self.banner)

        # ---------------------------------------------------------- status
        status_card = Card(padding=18, spacing=12)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.status_badge = Badge("Ocioso", "gray")
        self.phase_label = QLabel("Nenhuma varredura em andamento.")
        set_role(self.phase_label, "h3")
        self.elapsed_label = QLabel("")
        set_role(self.elapsed_label, "muted2")
        top.addWidget(self.status_badge)
        top.addWidget(self.phase_label, 1)
        top.addWidget(self.elapsed_label, 0)
        status_card.body.addLayout(top)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(9)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.hide()
        status_card.body.addWidget(self.progress)

        self.current_label = QLabel("")
        set_role(self.current_label, "muted2")
        self.current_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.current_label.hide()
        status_card.body.addWidget(self.current_label)

        stats = QHBoxLayout()
        stats.setSpacing(28)
        self.stat_seen = MiniStat("Arquivos vistos", "0")
        self.stat_analyzed = MiniStat("Analisados", "0")
        self.stat_cached = MiniStat("Ignorados (cache)", "0")
        self.stat_findings = MiniStat("Detecções", "0")
        self.stat_inaccessible = MiniStat("Inacessíveis", "0")
        self.stat_time = MiniStat("Tempo", "0s")
        for widget in (self.stat_seen, self.stat_analyzed, self.stat_cached,
                       self.stat_findings, self.stat_inaccessible, self.stat_time):
            stats.addWidget(widget)
        stats.addStretch(1)
        status_card.body.addLayout(stats)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.cancel_button = make_button("Cancelar varredura", "stop", kind="danger",
                                         tooltip="Interromper a varredura em andamento",
                                         clicked=self.cancel_scan)
        self.cancel_button.setEnabled(False)
        self.quarantine_screen_button = make_button(
            "Abrir quarentena", "quarantine",
            clicked=lambda: self._navigate("quarantine"))
        actions.addWidget(self.cancel_button)
        actions.addStretch(1)
        actions.addWidget(self.quarantine_screen_button)
        status_card.body.addLayout(actions)
        self.body.addWidget(status_card)

        # ------------------------------------------------------ personalizada
        custom_card = Card(padding=18, spacing=10)
        self.custom_button = make_button("Iniciar personalizada", "folder", kind="primary",
                                         tooltip="Varrer somente as pastas selecionadas",
                                         clicked=lambda: self.begin_scan("custom"))
        custom_card.body.addWidget(SectionHeader(
            "Varredura personalizada", self.custom_button))
        hint = QLabel("Selecione pastas específicas. A varredura é sempre recursiva e não segue "
                      "links/junctions.")
        set_role(hint, "muted2")
        hint.setWordWrap(True)
        custom_card.body.addWidget(hint)

        self.path_list = QListWidget()
        self.path_list.setFixedHeight(104)
        custom_card.body.addWidget(self.path_list)

        path_actions = QHBoxLayout()
        path_actions.setSpacing(8)
        add_button = make_button("Adicionar pasta", "folder", clicked=self.add_folder)
        remove_button = make_button("Remover", "x", clicked=self.remove_folder)
        clear_button = make_button("Limpar", "trash", clicked=self.clear_folders)
        self.exclusions_label = QLabel("")
        set_role(self.exclusions_label, "muted2")
        path_actions.addWidget(add_button)
        path_actions.addWidget(remove_button)
        path_actions.addWidget(clear_button)
        path_actions.addSpacing(10)
        path_actions.addWidget(self.exclusions_label, 1)
        custom_card.body.addLayout(path_actions)
        self.body.addWidget(custom_card)
        self._load_folders()

        # --------------------------------------------------------- resultados
        self.results_title = SectionHeader("Resultados")
        self.body.addWidget(self.results_title)

        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filtrar por caminho ou categoria…")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._render_results)
        self.risk_filter = QComboBox()
        self.risk_filter.addItems(["Todos os riscos", "Alto e crítico", "Origem confirmada"])
        self.risk_filter.currentIndexChanged.connect(self._render_results)
        filters.addWidget(self.search_input, 1)
        filters.addWidget(self.risk_filter, 0)
        self.body.addLayout(filters)

        results_card = Card(padding=14, spacing=10)
        self.results_table = DataTable(
            ["Risco", "Categoria", "Caminho", "Pontuação", "Origem", "Estado"],
            empty_icon="scanner", empty_title="Nenhum resultado",
            empty_text="Inicie uma varredura para analisar o computador.",
        )
        self.results_table.row_activated.connect(self._show_finding)
        self.results_table.selection_changed.connect(self._update_result_actions)
        self.results_table.set_column_widths([80, 145, 280, 85, 155, 110])
        results_card.body.addWidget(self.results_table)

        result_actions = QHBoxLayout()
        result_actions.setSpacing(8)
        self.details_button = make_button("Detalhes", "eye", clicked=self._details_selected)
        self.open_button = make_button("Abrir pasta", "folder", clicked=self._open_selected)
        self.quarantine_button = make_button("Isolar em quarentena", "quarantine", kind="danger",
                                             clicked=self._quarantine_selected)
        for button in (self.details_button, self.open_button, self.quarantine_button):
            button.setEnabled(False)
            result_actions.addWidget(button)
        result_actions.addStretch(1)
        results_card.body.addLayout(result_actions)

        note = QLabel("O Scanner não remove arquivos automaticamente. Detecções heurísticas "
                      "não são confirmações de malware; somente itens com hash na base local "
                      "são apresentados como assinatura confirmada.")
        set_role(note, "muted2")
        note.setWordWrap(True)
        results_card.body.addWidget(note)
        self.body.addWidget(results_card)

        self.footer_label = QLabel("")
        set_role(self.footer_label, "muted2")
        self.footer_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.body.addWidget(self.footer_label)
        self.body.addStretch(1)

        root.addWidget(make_scroll(content))
        self.results_table.table.horizontalHeader().setStretchLastSection(False)
        self.results_table.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self._update_exclusions_label()

    # ------------------------------------------------------------------ pastas
    def _load_folders(self) -> None:
        paths = self.context.settings.get("scan_directories", [])
        for path in paths:
            self.path_list.addItem(str(path))

    def _current_folders(self) -> list[str]:
        return [self.path_list.item(i).text() for i in range(self.path_list.count())]

    def _save_folders(self) -> None:
        paths = self._current_folders()
        self.context.settings.set("scan_directories", paths)
        try:
            self.context.settings.save()
        except OSError as exc:
            self.context.log.warning("Falha ao salvar as pastas da varredura: %s", exc)
            self.warn("Preferências não salvas", friendly_error(exc))

    def _update_exclusions_label(self) -> None:
        exclusions = self.context.settings.get("exclusions", [])
        count = len(exclusions)
        self.exclusions_label.setText(
            f"Exclusões aplicadas: {count}" if count else "Nenhuma exclusão configurada")

    def add_folder(self) -> None:
        start = self._current_folders()[-1] if self._current_folders() else str(Path.home())
        path = QFileDialog.getExistingDirectory(self, "Adicionar pasta à varredura", start)
        if not path:
            return
        path = str(Path(path))
        if not Path(path).is_dir():
            self.warn("Pasta inválida", "O caminho selecionado não é um diretório acessível.")
            return
        existing = {str(Path(p)) for p in self._current_folders()}
        if path in existing:
            return
        self.path_list.addItem(path)
        self._save_folders()

    def remove_folder(self) -> None:
        row = self.path_list.currentRow()
        if row >= 0:
            self.path_list.takeItem(row)
            self._save_folders()

    def clear_folders(self) -> None:
        if not self.path_list.count():
            return
        self.path_list.clear()
        self._save_folders()

    # ------------------------------------------------------------------ execução
    def begin_scan(self, kind: str = "quick") -> None:
        if self._running:
            self.warn("Varredura em andamento",
                      "Aguarde a varredura atual terminar ou cancele antes de iniciar outra.")
            return
        db = self.context.db
        if db is None:
            self.error("Banco de dados indisponível",
                       str(self.context.db_error or "A varredura não pode ser registrada."))
            return
        paths = None
        if kind == "custom":
            paths = self._current_folders()
            if not paths:
                self.warn("Nenhuma pasta selecionada",
                          "Adicione ao menos uma pasta para a varredura personalizada.")
                return
            missing = [p for p in paths if not Path(p).exists()]
            if missing:
                self.warn("Pasta indisponível",
                          "Remova ou corrija as pastas que não existem mais: "
                          + ", ".join(missing[:3]))
                return
        try:
            scanner = self.context.make_scanner()
        except Exception as exc:
            self.error("Não foi possível iniciar a varredura", friendly_error(exc))
            return

        exclusions = [str(p) for p in self.context.settings.get("exclusions", []) if str(p).strip()]
        self._set_running(True)
        self._scan_id = None
        self._findings = []
        self._last_result = None
        self._render_results()
        self.phase_label.setText("Iniciando varredura…")
        self.elapsed_label.setText("")
        self.current_label.setText("")
        self.current_label.hide()
        self.progress.setRange(0, 0)
        self.progress.show()
        self.status_badge.setText("Em andamento")
        self.status_badge.set_level("accent")
        self.banner.clear()
        self._set_stats(0, 0, 0, 0, 0, 0.0)
        self.footer_label.setText("")
        label = {"quick": "rápida", "full": "completa", "custom": "personalizada"}.get(kind, kind)
        self.info("Varredura iniciada", f"Varredura {label} em andamento. "
                                        "Você pode continuar navegando; o progresso continua aqui.")
        try:
            self._worker = self.tasks.start(
                make_scan_task(scanner, kind, paths, exclusions),
                on_success=self._on_scan_success,
                on_error=self._on_scan_error,
                on_progress=self._on_progress,
                on_status=self._on_status,
                on_cancelled=self._on_scan_cancelled,
                on_finished=self._on_scan_finished,
            )
        except Exception as exc:
            self._set_running(False)
            self._on_scan_error(friendly_error(exc), "")

    def cancel_scan(self) -> None:
        if not self._running or self._worker is None:
            return
        self.cancel_button.setEnabled(False)
        self.cancel_button.setText("Cancelando…")
        self.phase_label.setText("Solicitando cancelamento…")
        try:
            self._worker.cancel()
        except RuntimeError:
            pass
        self.warn("Cancelamento solicitado",
                  "A varredura será interrompida ao final da verificação atual.")

    def _set_running(self, running: bool) -> None:
        self._running = running
        self.quick_button.setEnabled(not running)
        self.full_button.setEnabled(not running)
        self.custom_button.setEnabled(not running)
        self.cancel_button.setEnabled(running)
        if running:
            self.cancel_button.setText("Cancelar varredura")
        self._update_result_actions()

    def _set_stats(self, seen, analyzed, cached, findings, inaccessible, elapsed) -> None:
        self.stat_seen.set_value(str(seen))
        self.stat_analyzed.set_value(str(analyzed))
        self.stat_cached.set_value(str(cached))
        self.stat_findings.set_value(str(findings))
        self.stat_inaccessible.set_value(str(inaccessible))
        self.stat_time.set_value(format_duration(elapsed))

    def _on_status(self, text: str) -> None:
        self.phase_label.setText(text)

    def _on_progress(self, progress) -> None:
        if not isinstance(progress, ScanProgress):
            return
        phase = str(progress.phase or "verificando").capitalize()
        self.phase_label.setText(f"{phase}…")
        self._set_stats(progress.files_seen, progress.files_analyzed, progress.files_cached,
                        progress.findings, progress.inaccessible, progress.elapsed)
        self.elapsed_label.setText(format_duration(progress.elapsed))
        current = str(progress.current or "")
        if current:
            self.current_label.setText(elide(current, 120))
            self.current_label.setToolTip(current)
            self.current_label.show()

    def _on_scan_success(self, result) -> None:
        if not isinstance(result, ScanResult):
            self._on_scan_error("O núcleo retornou um resultado inesperado.", "")
            return
        self._last_result = result
        self._scan_id = result.scan_id
        self._set_running(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.progress.show()
        self.current_label.hide()
        self._set_stats(result.files_seen, result.files_analyzed, result.files_cached,
                        len(result.findings), result.inaccessible, result.duration)
        self.elapsed_label.setText(format_duration(result.duration))
        self.phase_label.setText("Varredura concluída." if not result.cancelled
                                 else "Varredura interrompida.")
        self._load_findings(result.scan_id, fallback=result.findings)
        self._render_results()

        if result.cancelled:
            self.status_badge.setText("Interrompida")
            self.status_badge.set_level("warning")
            self.banner.set_message(
                "warning", "Varredura cancelada",
                f"{result.files_seen} arquivos vistos e {len(result.findings)} detecção(ões) "
                "parcial(is). Resultados podem estar incompletos.")
            self.warn("Varredura cancelada",
                      f"{len(result.findings)} detecção(ões) parcial(is) registradas.")
        elif result.findings:
            severe = any(f.risk >= 3 for f in result.findings)
            self.status_badge.setText("Concluída com detecções")
            self.status_badge.set_level("danger" if severe else "warning")
            self.banner.set_message(
                "danger" if severe else "warning",
                f"Varredura concluída com {len(result.findings)} detecção(ões)",
                "Nenhum arquivo foi removido. Revise os resultados, abra os detalhes ou use a "
                "quarentena com confirmação explícita.")
            self.warn("Varredura concluída com detecções",
                      f"{len(result.findings)} item(ns) encontrado(s). Nada foi removido.")
        else:
            self.status_badge.setText("Concluída sem detecções")
            self.status_badge.set_level("safe")
            self.banner.set_message(
                "success", "Nenhuma detecção nesta varredura",
                "Isso não substitui a proteção em tempo real do Windows Defender e não garante "
                "que o computador esteja livre de ameaças desconhecidas.")
            self.success("Varredura concluída",
                         "Nenhuma detecção registrada nesta varredura.")
        if result.errors:
            extra = (f" {len(result.errors)} arquivo(s) não puderam ser analisados; "
                     "veja o log para os detalhes.")
            current_title = self.banner.title_label.text()
            current_message = self.banner.message_label.text() + extra
            self.banner.set_message(self._banner_level(), current_title, current_message)
        self.footer_label.setText(
            f"Varredura #{result.scan_id} • {format_datetime(_now_iso())} • "
            f"{result.files_analyzed} arquivo(s) analisado(s).")

    def _banner_level(self) -> str:
        badge = self.status_badge.text()
        if badge == "Concluída sem detecções":
            return "success"
        if badge == "Interrompida":
            return "warning"
        if badge == "Concluída com detecções":
            return "danger" if self.status_badge.property("role") == "badgeRed" else "warning"
        return "info"

    def _load_findings(self, scan_id: int, fallback=None) -> None:
        db = self.context.db
        rows: list = []
        if db is not None:
            try:
                rows = db.list_findings(scan_id=scan_id)
            except Exception as exc:
                self.context.log.exception("Falha ao ler os resultados da varredura")
                self.warn("Resultados não confirmados pelo banco",
                          friendly_error(exc) + " Os dados exibidos vêm da resposta do núcleo.")
        if not rows and fallback:
            rows = [{
                "path": getattr(f, "path", ""),
                "sha256": getattr(f, "sha256", ""),
                "category": getattr(getattr(f, "category", ""), "value", getattr(f, "category", "")),
                "risk": getattr(getattr(f, "risk", None), "label", "SEGURO"),
                "score": getattr(f, "score", 0),
                "status": "open",
                "evidence_json": json.dumps(f.to_dict(), ensure_ascii=False),
            } for f in fallback]
        self._findings = rows

    def _on_scan_cancelled(self) -> None:
        self._set_running(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.status_badge.setText("Interrompida")
        self.status_badge.set_level("warning")
        self.phase_label.setText("Varredura interrompida.")
        self.banner.set_message("warning", "Varredura cancelada",
                                "Nenhum resultado parcial foi confirmado pelo núcleo.")
        self.warn("Varredura cancelada", "Nenhum resultado parcial foi confirmado.")

    def _on_scan_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Varredura falhou: %s", message)
        self._set_running(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.status_badge.setText("Falhou")
        self.status_badge.set_level("danger")
        self.phase_label.setText("Não foi possível concluir a varredura.")
        self.banner.set_message("danger", "Falha na varredura", message)
        self._render_results()
        self.error("Falha na varredura", message)

    def _on_scan_finished(self) -> None:
        self._worker = None
        self._running = False
        self._update_result_actions()
        # A varredura (concluída, falha ou cancelada) grava seu status no banco.
        self.emit_data_changed()
        if self.cancel_button.text() == "Cancelando…":
            self.cancel_button.setText("Cancelar varredura")
            self.cancel_button.setEnabled(False)

    # ------------------------------------------------------------------ resultados
    def _visible_findings(self) -> list:
        text = self.search_input.text().strip().casefold()
        mode = self.risk_filter.currentIndex()
        out = []
        for finding in self._findings:
            if mode == 1 and risk_order(finding.get("risk", "")) < 3:
                continue
            if mode == 2 and _origin(finding)[0] != "Assinatura confirmada":
                continue
            haystack = f"{finding.get('path', '')} {finding.get('category', '')}".casefold()
            if text and text not in haystack:
                continue
            out.append(finding)
        return out

    def _render_results(self) -> None:
        visible = self._visible_findings()[:MAX_RESULTS]
        count = len(self._findings)
        if count > MAX_RESULTS:
            self.results_title.title_label.setText(
                f"Resultados ({MAX_RESULTS} de {count} — refine o filtro)")
        elif count:
            self.results_title.title_label.setText(f"Resultados ({count})")
        else:
            self.results_title.title_label.setText("Resultados")
        if not self._findings:
            if self._running:
                self.results_table.set_empty("scanner", "Varredura em andamento",
                                             "Os resultados aparecerão quando ela terminar.")
            else:
                self.results_table.set_empty(
                    "scanner", "Nenhum resultado",
                    "Inicie uma varredura ou carregue o histórico para revisar detecções.")
        else:
            self.results_table.set_empty(
                "info", "Nenhum resultado para o filtro",
                "Ajuste a busca ou selecione outro nível de risco.")

        rows, payloads = [], []
        for finding in visible:
            risk = str(finding.get("risk") or "SEGURO")
            path = str(finding.get("path") or "—")
            origin, origin_color = _origin(finding)
            status = str(finding.get("status") or "open").lower()
            status_label = {"open": "Aberta", "quarantined": "Em quarentena",
                            "resolved": "Resolvida", "deleted": "Excluída"}.get(
                                status, status.replace("_", " ").title())
            rows.append([
                Cell(risk, sort_key=risk_order(risk), color=risk_color(risk), bold=True),
                Cell(str(finding.get("category") or "Indefinido")),
                Cell(elide(path, 70), tooltip=path),
                Cell(str(finding.get("score") or 0), sort_key=int(finding.get("score") or 0)),
                Cell(origin, color=origin_color),
                Cell(status_label),
            ])
            payloads.append(finding)
        self.results_table.set_rows(rows, payloads)
        self._update_result_actions()

    def _update_result_actions(self) -> None:
        selected = self.results_table.selected_payload()
        has_selection = isinstance(selected, dict)
        can_act = has_selection and not self._running and not self._quarantining
        self.details_button.setEnabled(has_selection)
        self.open_button.setEnabled(has_selection)
        self.quarantine_button.setEnabled(can_act)

    def _details_selected(self) -> None:
        finding = self.results_table.selected_payload()
        if isinstance(finding, dict):
            self._show_finding(finding)

    def _open_selected(self) -> None:
        finding = self.results_table.selected_payload()
        if not isinstance(finding, dict):
            return
        path = str(finding.get("path") or "")
        parent = Path(path).parent
        if not parent.is_dir():
            self.warn("Pasta indisponível", "O diretório deste item não existe mais.")
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(parent))):
            self.warn("Não foi possível abrir a pasta", str(parent))

    def _quarantine_selected(self) -> None:
        finding = self.results_table.selected_payload()
        if not isinstance(finding, dict) or self._quarantining:
            return
        path = str(finding.get("path") or "")
        risk = str(finding.get("risk") or "SEGURO")
        if not path or not Path(path).is_file():
            self.warn("Arquivo indisponível", "O arquivo não existe mais; nada foi alterado.")
            return
        quarantine = self.context.quarantine
        if quarantine is None:
            self.error("Quarentena indisponível",
                       friendly_error(self.context.quarantine_error or
                                      "Não foi possível inicializar a quarentena."))
            return
        if not self.confirm(
            "Isolar arquivo em quarentena",
            "O arquivo será movido para a quarentena criptografada do Sentinel e removido "
            "do local original.",
            f"Caminho: {path}\nRisco: {risk}\n\nVocê poderá restaurá-lo depois pela tela "
            "Quarentena, enquanto o item existir.",
            danger=True,
            confirm_text="Mover para quarentena",
            require_ack=True,
            ack_text="Entendo que o arquivo original será movido para a quarentena.",
        ):
            return
        evidences = _evidence_list(finding)
        self._quarantining = True
        self._update_result_actions()
        self.phase_label.setText("Isolando arquivo em quarentena…")
        self.tasks.start(
            make_quarantine_task(quarantine, path, evidences),
            on_success=lambda qid: self._on_quarantine_success(finding, qid),
            on_error=self._on_quarantine_error,
            on_finished=self._on_quarantine_finished,
        )

    def _on_quarantine_success(self, finding: dict, qid) -> None:
        db = self.context.db
        if db is not None and finding.get("id") is not None:
            try:
                db.set_finding_status(int(finding["id"]), "quarantined")
            except Exception:
                self.context.log.exception("Falha ao atualizar o estado da detecção")
        self.success("Arquivo isolado",
                     f"Item {short_hash(str(qid), 12)} confirmado na quarentena.")
        if self._scan_id is not None:
            self._load_findings(self._scan_id)
            self._render_results()
        self.phase_label.setText("Arquivo isolado em quarentena.")
        self.emit_data_changed()

    def _on_quarantine_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Quarentena falhou: %s", message)
        self.error("Não foi possível isolar o arquivo", message)
        self.phase_label.setText("A quarentena não foi concluída.")

    def _on_quarantine_finished(self) -> None:
        self._quarantining = False
        self._update_result_actions()

    def _show_finding(self, finding) -> None:
        if not isinstance(finding, dict):
            return
        payload = {}
        try:
            payload = json.loads(finding.get("evidence_json") or "{}")
        except (TypeError, ValueError):
            payload = {}
        origin, _ = _origin(finding)
        DetailDialog(
            self,
            "Detecção da varredura",
            "Resultado registrado pelo núcleo. Nenhum arquivo foi removido automaticamente.",
            fields=[
                ("Caminho", finding.get("path")),
                ("Risco", finding.get("risk")),
                ("Pontuação", finding.get("score")),
                ("Categoria", finding.get("category")),
                ("Origem", origin),
                ("SHA-256", finding.get("sha256")),
                ("Assinatura digital", payload.get("signature")),
            ],
            sections=[("Evidências", _evidence_list(finding) or "Nenhuma evidência detalhada.")],
            note="Heurísticas podem gerar falsos positivos. Só isole um arquivo após revisar "
                 "as evidências e confirmar que ele não é necessário.",
        ).exec()

    def _navigate(self, key: str) -> None:
        navigate = getattr(self.window(), "navigate", None)
        if callable(navigate):
            navigate(key)

    # ------------------------------------------------------------------ ativação
    def on_activate(self) -> None:
        super().on_activate()
        # Pastas e exclusões podem ter sido editadas na tela de Configurações.
        if not self._running:
            self.path_list.clear()
            self._load_folders()
        self._update_exclusions_label()
        if self._running or self._loaded_last:
            return
        self._loaded_last = True
        db = self.context.db
        if db is None:
            return
        try:
            scans = db.list_scans(limit=1)
        except Exception as exc:
            self.context.log.exception("Falha ao carregar a última varredura")
            self.banner.set_message("warning", "Histórico indisponível", friendly_error(exc))
            return
        if not scans:
            return
        scan = scans[0]
        self._scan_id = scan.get("id")
        self._load_findings(int(self._scan_id))
        self._render_results()
        status = str(scan.get("status") or "").lower()
        self._set_stats(scan.get("files_scanned") or 0, "—", "—", len(self._findings),
                        "—", 0.0)
        if status == "completed":
            self.status_badge.setText("Concluída com detecções" if self._findings
                                      else "Concluída sem detecções")
            self.status_badge.set_level("warning" if self._findings else "safe")
        elif status == "cancelled":
            self.status_badge.setText("Interrompida")
            self.status_badge.set_level("warning")
        elif status == "failed":
            self.status_badge.setText("Falhou")
            self.status_badge.set_level("danger")
        else:
            self.status_badge.setText("Não finalizada")
            self.status_badge.set_level("warning")
        self.phase_label.setText(
            f"Última varredura: {format_datetime(scan.get('finished') or scan.get('started'))}")
        self.progress.setRange(0, 100)
        self.progress.setValue(100 if status == "completed" else 0)
        self.progress.show()
        if status == "running":
            self.banner.set_message(
                "warning", "Última varredura não foi finalizada",
                "O registro ficou como 'em andamento'. Os resultados podem estar incompletos; "
                "execute uma nova varredura para confirmar o estado atual.")
        elif status == "failed":
            self.banner.set_message("danger", "A última varredura falhou",
                                    "Os resultados abaixo podem estar incompletos.")
        elif status == "cancelled":
            self.banner.set_message("warning", "A última varredura foi cancelada",
                                    "Os resultados abaixo são parciais.")
        elif self._findings:
            self.banner.set_message(
                "warning", f"Última varredura: {len(self._findings)} detecção(ões)",
                "Nada foi removido automaticamente. Revise os itens antes de qualquer ação.")
        else:
            self.banner.set_message(
                "success", "Última varredura sem detecções",
                "Isso não substitui a proteção em tempo real do Windows Defender.")


def _now_iso() -> str:
    from datetime import datetime
    return datetime.now().isoformat(timespec="seconds")
