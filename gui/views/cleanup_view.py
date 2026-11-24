"""Tela de Limpeza: análise conservadora, prévia individual e execução confirmada.

As categorias, os caminhos elegíveis, a estimativa e a remoção são obtidos
exclusivamente de ``core/cleanup.py``. A tela nunca escolhe diretórios
arbitrários, nunca segue links e não exibe o espaço estimado como se já tivesse
sido liberado.
"""
from __future__ import annotations

import time
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
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
from ..formatting import format_bytes, format_datetime
from ..workers.cleanup_worker import (
    ConfirmationRequired,
    make_analysis_task,
    make_clean_task,
)
from .base_view import BaseView

PREVIEW_LIMIT = 500


def _age_days(mtime) -> float | None:
    try:
        return max(0.0, (time.time() - float(mtime)) / 86400)
    except (TypeError, ValueError):
        return None


def _age_text(mtime) -> str:
    days = _age_days(mtime)
    if days is None:
        return "—"
    if days < 1:
        return "menos de 1 dia"
    return f"{int(days)} dia(s)"


class CleanupView(BaseView):
    KEY = "cleanup"
    TITLE = "Limpeza"
    SUBTITLE = "Limpeza conservadora de arquivos temporários"

    def __init__(self, context: AppContext, parent=None):
        self._categories: list = []
        self._category_by_key: dict = {}
        self._estimates: dict = {}
        self._preview: dict = {"files": [], "truncated": False, "errors": {}}
        self._analyzed = False
        self._busy = False
        self._worker = None
        self._worker_kind = ""
        self._needs_refresh = False
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

        self.analyze_button = make_button(
            "Analisar locais", "search", tooltip="Calcular estimativas e listar arquivos elegíveis",
            clicked=lambda: self.analyze(force=True))
        self.clean_button = make_button(
            "Limpar selecionados", "trash", kind="danger",
            tooltip="Remover somente os arquivos marcados, após confirmação",
            clicked=self.clean_selected)
        self.cancel_button = make_button("Cancelar", "stop", clicked=self.cancel)
        self.cancel_button.setEnabled(False)
        body.addWidget(PageHeader(
            self.TITLE, self.SUBTITLE,
            [self.analyze_button, self.clean_button, self.cancel_button]))

        self.banner = InfoBanner()
        body.addWidget(self.banner)

        status_card = Card(padding=16, spacing=10)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.status_badge = Badge("Aguardando", "gray")
        self.status_label = QLabel("A análise ainda não foi executada. Nada será removido sem confirmação.")
        set_role(self.status_label, "muted")
        self.status_label.setWordWrap(True)
        top.addWidget(self.status_badge)
        top.addWidget(self.status_label, 1)
        status_card.body.addLayout(top)
        stats = QHBoxLayout()
        stats.setSpacing(28)
        self.stat_estimate = MiniStat("Espaço estimado", "—")
        self.stat_files = MiniStat("Arquivos listados", "—")
        self.stat_selected = MiniStat("Arquivos marcados", "—")
        self.stat_freed = MiniStat("Bytes removidos", "—")
        for stat in (self.stat_estimate, self.stat_files, self.stat_selected, self.stat_freed):
            stats.addWidget(stat)
        stats.addStretch(1)
        status_card.body.addLayout(stats)
        body.addWidget(status_card)

        categories_card = Card(padding=14, spacing=10)
        categories_card.body.addWidget(self._section(
            "Categorias do núcleo", "Marque apenas as categorias que deseja analisar/limpar."))
        self.category_table = DataTable(
            ["", "Categoria", "Descrição", "Raízes", "Idade mínima", "Estimativa"],
            empty_icon="cleanup", empty_title="Nenhuma categoria disponível",
            empty_text="O núcleo não forneceu categorias de limpeza.")
        self.category_table.set_column_widths([55, 175, 215, 220, 100, 130])
        self.category_table.table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch)
        self.category_table.item_changed.connect(self._on_category_changed)
        categories_card.body.addWidget(self.category_table)
        body.addWidget(categories_card)

        preview_card = Card(padding=14, spacing=10)
        preview_card.body.addWidget(self._section(
            "Prévia individual", "Marque os arquivos que podem ser removidos; itens não marcados são ignorados."))
        self.preview_table = DataTable(
            ["", "Arquivo", "Caminho", "Tamanho", "Idade", "Categoria"],
            empty_icon="folder", empty_title="Nenhum arquivo listado",
            empty_text="Execute a análise para ver os arquivos elegíveis.")
        self.preview_table.set_column_widths([55, 160, 330, 100, 110, 175])
        self.preview_table.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self.preview_table.item_changed.connect(self._on_preview_changed)
        self.preview_table.row_activated.connect(self._show_file)
        preview_card.body.addWidget(self.preview_table)
        body.addWidget(preview_card)

        note = QLabel(
            "A estimativa é calculada antes da remoção e pode diferir do espaço efetivamente "
            "liberado no disco. Documentos, mídia, arquivos compactados, links/junctions e "
            "caminhos fora das raízes conhecidas são ignorados pelo núcleo. A Lixeira só é "
            "esvaziada com confirmação adicional e não possui prévia individual.")
        set_role(note, "muted2")
        note.setWordWrap(True)
        body.addWidget(note)
        body.addStretch(1)
        root.addWidget(make_scroll(content))

    @staticmethod
    def _section(title: str, hint: str) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        label = QLabel(title)
        set_role(label, "h3")
        description = QLabel(hint)
        set_role(description, "muted2")
        description.setWordWrap(True)
        layout.addWidget(label)
        layout.addWidget(description, 1)
        return widget

    # ------------------------------------------------------------------ análise
    def on_activate(self) -> None:
        super().on_activate()
        if not self._categories:
            self._load_categories()

    def _load_categories(self) -> bool:
        try:
            categories = self.context.make_cleanup_categories()
        except Exception as exc:
            self._show_error("Categorias indisponíveis", friendly_error(exc))
            return False
        if not isinstance(categories, list):
            self._show_error("Categorias indisponíveis", "O núcleo retornou uma lista inválida.")
            return False
        self._categories = categories
        self._category_by_key = {c.key: c for c in categories}
        self._render_categories()
        return True

    def analyze(self, force: bool = False) -> None:
        if self._busy:
            return
        if not self._categories and not self._load_categories():
            return
        if self.context.db is None:
            self._show_error("Banco indisponível",
                             str(self.context.db_error or "Não foi possível abrir o banco."))
            return
        self._start(make_analysis_task(self._categories, PREVIEW_LIMIT), "analysis")

    def cancel(self) -> None:
        if not self._busy or self._worker is None:
            return
        self.cancel_button.setEnabled(False)
        self.status_label.setText("Cancelamento solicitado; os resultados serão descartados…")
        try:
            self._worker.cancel()
        except RuntimeError:
            pass

    def _start(self, task, kind: str) -> None:
        self._busy = True
        self._worker_kind = kind
        self._needs_refresh = False
        self.status_badge.setText("Executando")
        self.status_badge.set_level("accent")
        self.cancel_button.setEnabled(True)
        self.analyze_button.setEnabled(False)
        self.clean_button.setEnabled(False)
        try:
            self._worker = self.tasks.start(
                task, on_success=self._on_success, on_error=self._on_error,
                on_status=self._on_status, on_cancelled=self._on_cancelled,
                on_finished=self._on_finished)
        except Exception as exc:
            self._busy = False
            self._show_error("Não foi possível iniciar a operação", friendly_error(exc))

    def _on_status(self, text: str) -> None:
        self.status_label.setText(text)

    def _on_success(self, result) -> None:
        if self._worker_kind == "analysis":
            if not isinstance(result, dict) or not isinstance(result.get("estimates"), dict) \
                    or not isinstance(result.get("preview"), dict):
                self._on_error("O núcleo retornou uma análise em formato inesperado.", "")
                return
            self._estimates = result["estimates"]
            self._preview = result["preview"]
            self._analyzed = True
            self.status_badge.setText("Analisado")
            self.status_badge.set_level("safe")
            self.status_label.setText(
                "Prévia concluída. Nenhum arquivo foi removido; marque os itens e confirme para limpar.")
            self._render_categories()
            self._render_preview()
            self._show_analysis_warnings()
            return
        if self._worker_kind == "clean":
            self._render_clean_result(result)
            self._needs_refresh = True

    def _show_analysis_warnings(self) -> None:
        errors = []
        for key, data in self._estimates.items():
            if data.get("error"):
                errors.append(f"{key}: {data['error']}")
        for key, message in (self._preview.get("errors") or {}).items():
            errors.append(f"{key}: {message}")
        if self._preview.get("truncated"):
            errors.append(f"Prévia limitada a {PREVIEW_LIMIT} arquivos; apenas os itens "
                          "marcados serão removidos.")
        if errors:
            self.banner.set_message("warning", "Análise parcial",
                                    " ".join(errors))
        else:
            self.banner.set_message("info", "Prévia disponível",
                                    "Estimativa e lista não alteram arquivos. "
                                    "A remoção depende de confirmação explícita.")

    def _render_clean_result(self, result) -> None:
        if not isinstance(result, dict) or not isinstance(result.get("results"), list):
            self._on_error("O núcleo não confirmou o resultado da limpeza.", "")
            return
        entries = result["results"]
        freed = sum(int(e.get("freed") or 0) for e in entries if isinstance(e, dict))
        deleted = sum(int(e.get("deleted") or 0) for e in entries if isinstance(e, dict))
        skipped = sum(int(e.get("skipped") or 0) for e in entries if isinstance(e, dict))
        errors = [msg for e in entries if isinstance(e, dict) for msg in (e.get("errors") or [])]
        self.stat_freed.set_value(format_bytes(freed))
        if result.get("cancelled"):
            self.status_badge.setText("Cancelada")
            self.status_badge.set_level("warning")
            self.status_label.setText("A limpeza foi cancelada; apenas arquivos já removidos foram contados.")
            self.banner.set_message("warning", "Limpeza cancelada",
                                    f"{deleted} arquivo(s) removido(s) antes do cancelamento.")
            return
        if errors or skipped:
            self.status_badge.setText("Parcial")
            self.status_badge.set_level("warning")
            self.status_label.setText(
                f"{deleted} arquivo(s) removido(s); {skipped} ignorado(s); {len(errors)} erro(s).")
            self.banner.set_message(
                "warning", "Limpeza parcial",
                "Arquivos em uso, protegidos ou com erro não foram removidos. " +
                " ".join(errors[:5]))
        else:
            self.status_badge.setText("Concluída")
            self.status_badge.set_level("safe")
            self.status_label.setText(f"{deleted} arquivo(s) removido(s) pelo núcleo.")
            self.banner.set_message(
                "success", "Limpeza concluída",
                f"Bytes de arquivos removidos: {format_bytes(freed)}. "
                "O espaço efetivamente livre no disco pode ser diferente.")
        self.success("Limpeza executada", self.status_label.text())

    def _on_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Limpeza falhou: %s", message)
        self.status_badge.setText("Falhou")
        self.status_badge.set_level("danger")
        self.status_label.setText(message)
        self.banner.set_message("danger", "Operação não concluída", message)
        self.error("Limpeza", message)
        if self._worker_kind == "clean":
            self._needs_refresh = True

    def _show_error(self, title: str, message: str) -> None:
        self._busy = False
        self.status_badge.setText("Indisponível")
        self.status_badge.set_level("danger")
        self.status_label.setText(message)
        self.banner.set_message("danger", title, message)
        self.category_table.clear()
        self.preview_table.clear()
        self.error(title, message)

    def _on_cancelled(self) -> None:
        self.status_badge.setText("Cancelado")
        self.status_badge.set_level("warning")
        self.status_label.setText("Operação cancelada; nenhum resultado parcial foi aplicado.")
        self.banner.set_message("warning", "Operação cancelada",
                                "A prévia anterior foi mantida e nenhum arquivo foi removido.")
        self.warn("Limpeza", "Operação cancelada")
        self._needs_refresh = self._worker_kind == "clean"

    def _on_finished(self) -> None:
        self._busy = False
        self._worker = None
        self._worker_kind = ""
        self.cancel_button.setEnabled(False)
        self.analyze_button.setEnabled(True)
        self.clean_button.setEnabled(True)
        needs_refresh = self._needs_refresh
        self._needs_refresh = False
        self._update_actions()
        if needs_refresh:
            self.analyze(force=True)

    # ------------------------------------------------------------------ tabelas
    def _render_categories(self) -> None:
        rows, payloads = [], []
        for category in self._categories:
            data = self._estimates.get(category.key) if self._analyzed else None
            estimate = "—"
            if data and not data.get("error"):
                estimate = f"{format_bytes(data.get('size'))} / {int(data.get('count') or 0)}"
            elif data and data.get("error"):
                estimate = "erro na análise"
            roots = ", ".join(str(r) for r in category.roots) or "—"
            rows.append([
                Cell("", checkable=True, checked=bool(category.default_selected)),
                Cell(category.name, bold=True),
                Cell(elide(category.description, 60), tooltip=category.description),
                Cell(elide(roots, 70), tooltip=roots),
                Cell(f"{category.min_age_days:g} dia(s)" if category.min_age_days else "—"),
                Cell(estimate),
            ])
            payloads.append(category)
        self.category_table.set_rows(rows, payloads)
        self._render_stats()

    def _render_preview(self) -> None:
        files = self._preview.get("files") or []
        rows, payloads = [], []
        for item in files:
            key = str(item.get("category_key") or "")
            category = self._category_by_key.get(key)
            checked = bool(category and category.default_selected)
            path = str(item.get("path") or "")
            rows.append([
                Cell("", checkable=True, checked=checked),
                Cell(elide(path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] or "—", 32), tooltip=path),
                Cell(elide(path, 80), tooltip=path),
                Cell(format_bytes(item.get("size")), sort_key=int(item.get("size") or 0)),
                Cell(_age_text(item.get("mtime")), sort_key=_age_days(item.get("mtime")) or 0),
                Cell(str(item.get("category") or "—")),
            ])
            payloads.append(item)
        self.preview_table.set_rows(rows, payloads)
        self._render_stats()

    def _render_stats(self) -> None:
        if not self._analyzed:
            self.stat_estimate.set_value("—")
            self.stat_files.set_value("—")
        else:
            total = sum(int(v.get("size") or 0) for v in self._estimates.values()
                        if isinstance(v, dict) and not v.get("error"))
            self.stat_estimate.set_value(format_bytes(total))
            self.stat_files.set_value(str(len(self._preview.get("files") or [])))
        selected = self._selected_files()
        self.stat_selected.set_value(str(len(selected)) if self._analyzed else "—")

    def _on_category_changed(self, payload, column, checked) -> None:
        if column != 0:
            return
        self._render_stats()
        self._update_actions()

    def _on_preview_changed(self, payload, column, checked) -> None:
        if column != 0:
            return
        self._render_stats()
        self._update_actions()

    # ------------------------------------------------------------------ ações
    def _selected_categories(self) -> list:
        return [c for c in self.category_table.checked_payloads(0)
                if hasattr(c, "key") and hasattr(c, "kind")]

    def _selected_files(self) -> list[dict]:
        selected_keys = {c.key for c in self._selected_categories()}
        return [item for item in self.preview_table.checked_payloads(0)
                if isinstance(item, dict) and item.get("category_key") in selected_keys]

    def _update_actions(self) -> None:
        self.clean_button.setEnabled(not self._busy and self._analyzed and
                                      bool(self._selected_categories() or self._selected_files()))
        self.analyze_button.setEnabled(not self._busy)
        self.cancel_button.setEnabled(self._busy)

    def _show_file(self, payload) -> None:
        if not isinstance(payload, dict):
            return
        DetailDialog(
            self, "Arquivo elegível para limpeza",
            "Item listado pelo núcleo; nenhuma ação foi executada.",
            fields=[("Arquivo", str(payload.get("path") or "—")),
                    ("Caminho", str(payload.get("path") or "—")),
                    ("Tamanho", format_bytes(payload.get("size"))),
                    ("Idade", _age_text(payload.get("mtime"))),
                    ("Categoria", str(payload.get("category") or "—"))],
            note="A remoção depende da revalidação do núcleo no momento da limpeza.",
        ).exec()

    def clean_selected(self) -> None:
        if self._busy or not self._analyzed or self.context.db is None:
            return
        categories = self._selected_categories()
        files = self._selected_files()
        selected_keys = {c.key for c in categories}
        paths_by_key: dict[str, set[str]] = {}
        for item in files:
            paths_by_key.setdefault(str(item.get("category_key")), set()).add(str(item.get("path")))
        # Categorias sem prévia marcada não são limpas: nunca removemos "tudo" a partir da tela.
        effective = [c for c in categories
                     if c.kind == "recycle" or paths_by_key.get(c.key)]
        if not effective:
            self.warn("Nada selecionado", "Marque arquivos na prévia ou selecione a Lixeira.")
            return
        recycle = any(c.kind == "recycle" for c in effective)
        details = "\n".join(
            f"- {c.name}: {len(paths_by_key.get(c.key, ())) or ('lixeira' if c.kind == 'recycle' else 0)} item(s)"
            for c in effective)
        details += (f"\n\nEspaço estimado dos arquivos marcados: "
                    f"{format_bytes(sum(int(f.get('size') or 0) for f in files))}")
        if recycle:
            details += ("\n\nA Lixeira de todas as unidades será esvaziada pelo Windows. "
                        "Não há prévia individual e esta ação não pode ser desfeita.")
        if not self.confirm(
            "Limpar arquivos selecionados",
            "Somente os arquivos marcados serão removidos. O núcleo revalida cada caminho "
            "antes da exclusão; arquivos em uso ou protegidos podem ser ignorados.",
            details,
            danger=True,
            confirm_text="Limpar arquivos marcados",
            require_ack=True,
            ack_text=("Entendo que a Lixeira será esvaziada e que a limpeza é irreversível."
                      if recycle else
                      "Entendo que os arquivos marcados serão removidos definitivamente."),
        ):
            return
        try:
            task = make_clean_task(
                effective, self.context.db, confirmed=True,
                only_paths=paths_by_key, include_recycle=recycle)
        except ConfirmationRequired as exc:
            self.error("Limpeza recusada", str(exc))
            return
        self._start(task, "clean")
