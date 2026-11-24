"""Tela de Quarentena: consulta, restauração e exclusão confirmadas.

Toda leitura e toda mutação passam por ``core/quarantine.py``. A tela nunca
abre arquivos ``.qz``, nunca toca na criptografia e nunca remove arquivos por
conta própria. O estado exibido vem do banco, incluindo falhas e operações
interrompidas; uma operação só é anunciada como concluída após o retorno real
do núcleo.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
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
from ..formatting import (
    format_bytes,
    format_datetime,
    parse_datetime,
    quarantine_status,
    short_hash,
    status_color,
)
from ..workers.quarantine_worker import (
    make_delete_task,
    make_quarantine_list_task,
    make_restore_task,
)
from .base_view import BaseView

STATUS_FILTERS = [
    ("Todos os estados", None),
    ("Isolados", "quarantined"),
    ("Em andamento", ("pending", "ready", "restoring", "deleting")),
    ("Restaurados", "restored"),
    ("Excluídos", "deleted"),
    ("Falhas", "failed"),
]
ORDER_OPTIONS = [
    ("Mais recentes", "date_desc"),
    ("Mais antigos", "date_asc"),
    ("Nome original", "name"),
    ("Maior tamanho", "size"),
]


def _meta(record: dict) -> dict:
    """Lê metadados apenas para apresentação; nunca altera nem descriptografa."""
    try:
        payload = json.loads(record.get("meta_json") or "{}")
        return payload if isinstance(payload, dict) else {}
    except (TypeError, ValueError):
        return {}


def _evidences(record: dict) -> list[str]:
    try:
        payload = json.loads(record.get("evidence_json") or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(payload, list):
        return []
    return [f"[{(e.get('weight') if isinstance(e, dict) else '')}] "
            f"{e.get('description', '') if isinstance(e, dict) else e}"
            for e in payload]


class QuarantineView(BaseView):
    KEY = "quarantine"
    TITLE = "Quarentena"
    SUBTITLE = "Itens isolados com restauração e exclusão confirmadas"

    def __init__(self, context: AppContext, parent=None):
        self._items: list[dict] = []
        self._loaded = False
        self._busy = False
        self._worker = None
        self._worker_kind = ""
        self._checked_at = 0.0
        self._needs_refresh = False
        self._focus_id = ""
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
            "Atualizar lista", "refresh", tooltip="Reler os registros do banco",
            clicked=lambda: self.refresh(force=True))
        self.details_button = make_button("Detalhes", "eye", clicked=self._show_selected)
        self.restore_button = make_button(
            "Restaurar", "restore", tooltip="Restaurar o item selecionado (exige confirmação)",
            clicked=self._restore_selected)
        self.delete_button = make_button(
            "Excluir definitivamente", "trash", kind="danger",
            tooltip="Remover a cópia isolada (irreversível, exige confirmação)",
            clicked=self._delete_selected)
        body.addWidget(PageHeader(
            self.TITLE, self.SUBTITLE,
            [self.refresh_button, self.details_button, self.restore_button, self.delete_button]))

        self.banner = InfoBanner()
        body.addWidget(self.banner)

        status_card = Card(padding=16, spacing=10)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.status_badge = Badge("Aguardando", "gray")
        self.status_label = QLabel("A lista ainda não foi carregada.")
        set_role(self.status_label, "muted")
        self.status_label.setWordWrap(True)
        self.cancel_button = make_button(
            "Cancelar consulta", "stop", tooltip="Descartar a consulta em andamento",
            clicked=self.cancel)
        self.cancel_button.setEnabled(False)
        top.addWidget(self.status_badge)
        top.addWidget(self.status_label, 1)
        top.addWidget(self.cancel_button)
        status_card.body.addLayout(top)

        stats = QHBoxLayout()
        stats.setSpacing(28)
        self.stat_isolated = MiniStat("Isolados", "—")
        self.stat_pending = MiniStat("Em andamento", "—")
        self.stat_restored = MiniStat("Restaurados", "—")
        self.stat_deleted = MiniStat("Excluídos", "—")
        for widget in (self.stat_isolated, self.stat_pending,
                       self.stat_restored, self.stat_deleted):
            stats.addWidget(widget)
        stats.addStretch(1)
        status_card.body.addLayout(stats)
        body.addWidget(status_card)

        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Buscar por nome, caminho, ID ou hash…")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._render)
        self.status_filter = QComboBox()
        for label, _value in STATUS_FILTERS:
            self.status_filter.addItem(label)
        self.status_filter.currentIndexChanged.connect(self._render)
        self.order_combo = QComboBox()
        for label, _value in ORDER_OPTIONS:
            self.order_combo.addItem(label)
        self.order_combo.currentIndexChanged.connect(self._render)
        filters.addWidget(self.search_input, 1)
        filters.addWidget(self.status_filter, 0)
        filters.addWidget(self.order_combo, 0)
        body.addLayout(filters)

        table_card = Card(padding=14, spacing=10)
        self.table = DataTable(
            ["ID", "Nome original", "Caminho original", "Isolado em", "Tamanho", "Estado", "SHA-256"],
            empty_icon="quarantine",
            empty_title="Nenhum item na quarentena",
            empty_text="Atualize a lista para consultar os registros do núcleo.",
        )
        self.table.setMinimumHeight(400)
        self.table.row_activated.connect(self._show_entry)
        self.table.selection_changed.connect(self._update_actions)
        self.table.set_column_widths([100, 175, 245, 140, 100, 110, 190])
        self.table.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        table_card.body.addWidget(self.table)

        note = QLabel(
            "A criptografia, o journal e a recuperação de interrupções são executados pelo núcleo. "
            "A preservação de ACL/atributos no Windows é feita com o melhor esforço disponível, "
            "sem garantia em todos os sistemas de arquivos. Restaurar pode sobrescrever um arquivo "
            "existente; a exclusão definitiva é irreversível.")
        set_role(note, "muted2")
        note.setWordWrap(True)
        table_card.body.addWidget(note)
        body.addWidget(table_card)

        self.footer_label = QLabel("")
        set_role(self.footer_label, "muted2")
        self.footer_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        body.addWidget(self.footer_label)
        body.addStretch(1)

        root.addWidget(make_scroll(content))
        self._update_actions()

    # ------------------------------------------------------------------ consulta
    def on_activate(self) -> None:
        super().on_activate()
        stale = not self._checked_at or (time.monotonic() - self._checked_at) >= 60
        if not self._loaded or stale:
            self.refresh(force=False)

    def refresh(self, force: bool = True) -> None:
        if self._busy:
            return
        if not force and self._checked_at and (time.monotonic() - self._checked_at) < 20:
            return
        service = self.context.quarantine
        if service is None:
            self._show_error("Quarentena indisponível",
                             str(self.context.quarantine_error or
                                 "O núcleo não pôde inicializar a quarentena."))
            return
        self._start(make_quarantine_list_task(service, status=None), "list")

    def cancel(self) -> None:
        if not self._busy or self._worker_kind != "list" or self._worker is None:
            return
        self.cancel_button.setEnabled(False)
        self.status_badge.setText("Cancelando")
        self.status_badge.set_level("warning")
        self.status_label.setText("Cancelamento solicitado; a lista anterior será mantida…")
        try:
            self._worker.cancel()
        except RuntimeError:
            pass

    def _start(self, task, kind: str) -> None:
        self._busy = True
        self._worker_kind = kind
        self._needs_refresh = False
        if kind == "list":
            self.status_badge.setText("Consultando")
            self.status_badge.set_level("accent")
            self.status_label.setText("Lendo os registros de quarentena…")
            self.banner.set_message("info", "Consulta em andamento",
                                    "Nenhuma operação destrutiva está sendo executada.")
        else:
            self.status_badge.setText("Executando")
            self.status_badge.set_level("accent")
            self.status_label.setText("Aguardando a confirmação do núcleo…")
        try:
            self._worker = self.tasks.start(
                task,
                on_success=self._on_success,
                on_error=self._on_error,
                on_status=self._on_status,
                on_cancelled=self._on_cancelled,
                on_finished=self._on_finished,
            )
        except Exception as exc:
            self._busy = False
            self._worker_kind = ""
            self._show_error("Não foi possível iniciar a operação", friendly_error(exc))

    def _on_status(self, text: str) -> None:
        self.status_label.setText(text)

    def _on_success(self, result) -> None:
        kind = self._worker_kind
        if kind == "list":
            if not isinstance(result, (list, tuple)):
                self._on_error("O núcleo retornou uma resposta inesperada ao listar a quarentena.", "")
                return
            self._items = [dict(item) for item in result]
            self._loaded = True
            self._checked_at = time.monotonic()
            self.status_badge.setText("Atualizado")
            self.status_badge.set_level("safe")
            self.status_label.setText(f"{len(self._items)} registro(s) consultado(s).")
            self.banner.clear()
            self.footer_label.setText(
                f"Última consulta: {format_datetime(datetime.now())}  •  "
                "Estados e hashes são os registrados pelo núcleo; não são uma nova verificação.")
            self._render()
            if self._focus_id:
                for row in range(self.table.row_count()):
                    item = self.table.table.item(row, 0)
                    payload = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
                    if isinstance(payload, dict) and str(payload.get("id")) == self._focus_id:
                        self.table.table.setCurrentCell(row, 0)
                        break
                self._focus_id = ""
            return
        if kind == "restore":
            if not result:
                self._on_error("O núcleo não confirmou o destino da restauração.", "")
                return
            dest = str(result)
            self.status_badge.setText("Restaurado")
            self.status_badge.set_level("safe")
            self.status_label.setText(f"Item restaurado para: {dest}")
            self.banner.set_message("success", "Restauração confirmada", f"Destino: {dest}")
            self.success("Restauração concluída", dest)
        elif kind == "delete":
            self.status_badge.setText("Excluído")
            self.status_badge.set_level("gray")
            self.status_label.setText("O núcleo confirmou a exclusão definitiva do item.")
            self.banner.set_message("success", "Exclusão definitiva confirmada",
                                    "A cópia isolada foi removida pelo núcleo.")
            self.success("Exclusão definitiva concluída")
        self._needs_refresh = True

    def _on_error(self, message: str, details: str = "") -> None:
        self.context.log.warning("Operação de quarentena falhou: %s", message)
        self.status_badge.setText("Falhou")
        self.status_badge.set_level("danger")
        self.status_label.setText(message)
        self.banner.set_message("danger", "Operação não confirmada", message)
        self.error("Quarentena", message)
        if self._worker_kind != "list":
            self._needs_refresh = True

    def _show_error(self, title: str, message: str) -> None:
        self._busy = False
        self._loaded = False
        self.status_badge.setText("Indisponível")
        self.status_badge.set_level("danger")
        self.status_label.setText(message)
        self.banner.set_message("danger", title, message)
        self.table.set_empty("alert", title, "Nenhum registro pôde ser consultado.")
        self.table.clear()
        self._render_stats()
        self._update_actions()
        self.error(title, message)

    def _on_cancelled(self) -> None:
        self.status_badge.setText("Cancelado")
        self.status_badge.set_level("warning")
        self.status_label.setText("Operação cancelada; nenhum resultado parcial foi aplicado.")
        if self._worker_kind == "list":
            self.banner.set_message("warning", "Consulta cancelada",
                                    "A lista anterior foi mantida.")
            self.warn("Consulta cancelada", "A lista de quarentena não foi atualizada.")
        else:
            self.banner.set_message("warning", "Operação cancelada",
                                    "O núcleo pode ter registrado uma operação interrompida; "
                                    "a lista será recarregada.")
            self.warn("Operação cancelada")
            self._needs_refresh = True

    def _on_finished(self) -> None:
        self._busy = False
        self._worker = None
        self._worker_kind = ""
        self.cancel_button.setEnabled(False)
        self.refresh_button.setEnabled(True)
        needs_refresh = self._needs_refresh
        self._needs_refresh = False
        self._update_actions()
        if needs_refresh:
            self.refresh(force=True)

    # ------------------------------------------------------------------ filtros
    def _visible_items(self) -> list[dict]:
        text = self.search_input.text().strip().casefold()
        index = self.status_filter.currentIndex()
        selected = STATUS_FILTERS[index][1] if 0 <= index < len(STATUS_FILTERS) else None
        order = ORDER_OPTIONS[self.order_combo.currentIndex()][1] \
            if 0 <= self.order_combo.currentIndex() < len(ORDER_OPTIONS) else "date_desc"
        items = []
        for record in self._items:
            status = str(record.get("status") or "")
            if selected is not None:
                if isinstance(selected, tuple):
                    if status not in selected:
                        continue
                elif status != selected:
                    continue
            haystack = " ".join(str(record.get(k) or "") for k in
                                ("id", "original_path", "sha256", "stored_name")) .casefold()
            if text and text not in haystack:
                continue
            items.append(record)
        if order == "name":
            items.sort(key=lambda r: str(Path(r.get("original_path") or "").name).casefold())
        elif order == "size":
            items.sort(key=lambda r: -int(r.get("size") or 0))
        elif order == "date_asc":
            items.sort(key=lambda r: (parse_datetime(r.get("ts")) or datetime.min).timestamp())
        else:
            items.sort(key=lambda r: (parse_datetime(r.get("ts")) or datetime.min).timestamp(),
                       reverse=True)
        return items

    def _render(self) -> None:
        if not self._items:
            self.table.set_empty("quarantine", "Nenhum item na quarentena",
                                 "Use Atualizar lista para consultar os registros do núcleo.")
        elif not self._visible_items():
            self.table.set_empty("info", "Nenhum item para o filtro",
                                 "Ajuste a busca ou o estado selecionado.")
        rows, payloads = [], []
        for record in self._visible_items():
            label, level = quarantine_status(record.get("status"))
            rows.append([
                Cell(str(record.get("id") or "—")),
                Cell(elide(Path(record.get("original_path") or "").name or "—", 40),
                     tooltip=Path(record.get("original_path") or "").name),
                Cell(elide(record.get("original_path") or "—", 60),
                     tooltip=record.get("original_path") or ""),
                Cell(format_datetime(record.get("ts")),
                     sort_key=(parse_datetime(record.get("ts")) or datetime.min).timestamp()),
                Cell(format_bytes(record.get("size")), sort_key=int(record.get("size") or 0)),
                Cell(label, sort_key=label, color=status_color(level), bold=True),
                Cell(short_hash(record.get("sha256")), tooltip=record.get("sha256") or ""),
            ])
            payloads.append(record)
        self.table.set_rows(rows, payloads)
        self._render_stats()
        self._update_actions()

    def _render_stats(self) -> None:
        records = self._items if self._loaded else []
        self.stat_isolated.set_value(
            str(sum(1 for r in records if r.get("status") == "quarantined")) if self._loaded else "—")
        self.stat_pending.set_value(str(sum(1 for r in records if r.get("status") in
                                            ("pending", "ready", "restoring", "deleting")))
                                    if self._loaded else "—")
        self.stat_restored.set_value(
            str(sum(1 for r in records if r.get("status") == "restored")) if self._loaded else "—")
        self.stat_deleted.set_value(
            str(sum(1 for r in records if r.get("status") == "deleted")) if self._loaded else "—")

    # ------------------------------------------------------------------ ações
    def _selected(self) -> dict | None:
        payload = self.table.selected_payload()
        return payload if isinstance(payload, dict) else None

    def _update_actions(self) -> None:
        record = self._selected()
        ready = isinstance(record, dict) and record.get("status") == "quarantined"
        self.details_button.setEnabled(record is not None)
        self.restore_button.setEnabled(ready and not self._busy)
        self.delete_button.setEnabled(ready and not self._busy)
        self.refresh_button.setEnabled(not self._busy)
        if record is not None and not ready:
            label, _level = quarantine_status(record.get("status"))
            tooltip = f"Item com estado '{label}'; somente itens isolados podem ser alterados."
            self.restore_button.setToolTip(tooltip)
            self.delete_button.setToolTip(tooltip)
        else:
            self.restore_button.setToolTip("Restaurar o item (exige confirmação).")
            self.delete_button.setToolTip("Excluir a cópia isolada (irreversível).")

    def _show_selected(self) -> None:
        record = self._selected()
        if record is not None:
            self._show_entry(record)

    def _show_entry(self, record) -> None:
        if not isinstance(record, dict):
            return
        meta = _meta(record)
        label, _level = quarantine_status(record.get("status"))
        integrity = "SHA-256 e tamanho registrados" if record.get("sha256") else \
                    "Hash não registrado pelo núcleo"
        if meta.get("wrapped_key"):
            integrity += "; chave protegida (material não exibido)"
        fields = [
            ("ID", record.get("id")),
            ("Nome original", Path(record.get("original_path") or "").name or "—"),
            ("Caminho original", record.get("original_path")),
            ("Isolado em", format_datetime(record.get("ts"))),
            ("Tamanho", format_bytes(record.get("size"))),
            ("SHA-256", record.get("sha256") or "—"),
            ("Estado", label),
            ("Restaurado para", meta.get("restored_to") or "—"),
            ("Integridade registrada", integrity),
            ("Formato", str(meta.get("version") or "—")),
        ]
        sections = [("Evidências registradas", _evidences(record) or
                     ["Nenhuma evidência registrada no banco."])]
        DetailDialog(
            self,
            f"Item de quarentena — {record.get('id')}",
            "Dados lidos do banco pelo núcleo. Nenhuma verificação criptográfica foi refeita aqui.",
            fields=fields,
            sections=sections,
            note=("Os metadados de integridade são os gravados durante a operação. "
                  "A restauração e a exclusão continuam sendo executadas e validadas pelo núcleo."),
        ).exec()

    def _restore_selected(self) -> None:
        record = self._selected()
        if record is None or self._busy or record.get("status") != "quarantined":
            return
        self._focus_id = str(record.get("id") or "")
        original = str(record.get("original_path") or "")
        destination = original
        dest_path = Path(destination) if destination else None
        needs_picker = dest_path is None or not dest_path.parent.is_dir() or dest_path.exists()
        if needs_picker:
            chosen, _filter = QFileDialog.getSaveFileName(
                self, "Destino da restauração", original, "Todos os arquivos (*)")
            if not chosen:
                return
            destination = chosen
        dest_path = Path(destination)
        overwrite = dest_path.exists()
        details = (f"ID: {record.get('id')}\n"
                   f"Nome original: {dest_path.name}\n"
                   f"Destino: {destination}\n"
                   f"Tamanho: {format_bytes(record.get('size'))}\n"
                   f"SHA-256: {short_hash(record.get('sha256'))}")
        if overwrite:
            details += ("\n\nO destino JÁ EXISTE e será substituído. O núcleo tenta "
                        "preservar o conteúdo anterior em backup antes da substituição.")
        if not self.confirm(
            "Restaurar item da quarentena",
            "O arquivo será escrito no destino informado somente se o núcleo "
            "confirmar a integridade e a operação.",
            details,
            danger=overwrite,
            confirm_text="Restaurar arquivo",
            require_ack=True,
            ack_text=("Entendo que o arquivo existente será sobrescrito."
                      if overwrite else
                      "Entendo que o arquivo será gravado no destino informado."),
        ):
            return
        self._start(make_restore_task(
            self.context.quarantine, str(record.get("id")),
            destination=destination, overwrite=overwrite, confirmed=True), "restore")

    def _delete_selected(self) -> None:
        record = self._selected()
        if record is None or self._busy or record.get("status") != "quarantined":
            return
        self._focus_id = str(record.get("id") or "")
        details = (f"ID: {record.get('id')}\n"
                   f"Caminho original: {record.get('original_path')}\n"
                   f"Tamanho: {format_bytes(record.get('size'))}\n"
                   f"SHA-256: {short_hash(record.get('sha256'))}")
        if not self.confirm(
            "Excluir definitivamente da quarentena",
            "A cópia cifrada e a chave deste item serão removidas. Esta operação "
            "é IRREVERSÍVEL e o arquivo original NÃO será recuperável por esta ferramenta.",
            details,
            danger=True,
            confirm_text="Excluir definitivamente",
            require_ack=True,
            ack_text="Entendo que a exclusão é irreversível e o item não poderá ser restaurado.",
        ):
            return
        self._start(make_delete_task(
            self.context.quarantine, str(record.get("id")), confirmed=True), "delete")
