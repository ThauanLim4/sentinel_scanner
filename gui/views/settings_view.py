"""Tela de Configurações: preferências com efeito real e verificável.

Todas as opções exibidas são consumidas pelo núcleo ou pela janela principal:
tema, notificações não críticas, confirmação ao fechar durante operações,
número de threads/limite de CPU da varredura, pastas e exclusões usadas pelo
`Scanner.run(..., exclude_paths=...)` e nível de log. Nenhuma opção decorativa
é apresentada: idioma é fixo e nenhuma proteção do Windows é alterada aqui.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core import config
from ..components.common import (
    Badge,
    Card,
    FieldRow,
    InfoBanner,
    PageHeader,
    SectionHeader,
    Separator,
    make_button,
    make_scroll,
    set_role,
)
from ..context import AppContext
from ..errors import friendly_error
from ..formatting import format_time
from .base_view import BaseView

THEMES = [("Escuro", "dark"), ("Claro", "light")]
LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR"]


class SettingsView(BaseView):
    KEY = "settings"
    TITLE = "Configurações"
    SUBTITLE = "Preferências da interface, exclusões e desempenho"

    def __init__(self, context: AppContext, parent=None):
        self._loading = False
        self._dirty = False
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

        self.save_button = make_button(
            "Salvar alterações", "check", kind="primary",
            tooltip="Gravar e aplicar imediatamente tema e nível de log",
            clicked=self.save)
        self.reload_button = make_button(
            "Recarregar", "refresh", tooltip="Reler o arquivo de preferências",
            clicked=self.reload)
        self.reset_button = make_button(
            "Restaurar padrões", "restore", kind="danger",
            tooltip="Substituir todas as preferências pelos valores iniciais",
            clicked=self.reset_defaults)
        body.addWidget(PageHeader(
            self.TITLE, self.SUBTITLE,
            [self.save_button, self.reload_button, self.reset_button]))

        self.banner = InfoBanner()
        body.addWidget(self.banner)

        status_card = Card(padding=16, spacing=8)
        status_row = QHBoxLayout()
        status_row.setSpacing(10)
        self.status_badge = Badge("Sem alterações", "gray")
        self.status_label = QLabel(
            "As preferências ficam em data/gui_settings.json. Tema e nível de log são "
            "aplicados ao salvar; pastas e exclusões valem para a próxima varredura.")
        set_role(self.status_label, "muted")
        self.status_label.setWordWrap(True)
        status_row.addWidget(self.status_badge)
        status_row.addWidget(self.status_label, 1)
        status_card.body.addLayout(status_row)
        self.footer_label = QLabel("")
        set_role(self.footer_label, "muted2")
        status_card.body.addWidget(self.footer_label)
        body.addWidget(status_card)

        appearance = Card(padding=16, spacing=10)
        appearance.body.addWidget(SectionHeader("Aparência e comportamento"))
        self.theme_combo = QComboBox()
        for label, _value in THEMES:
            self.theme_combo.addItem(label)
        self.notifications_check = QCheckBox("Mostrar notificações não críticas")
        self.close_check = QCheckBox(
            "Confirmar ao fechar enquanto houver operação em andamento")
        for widget in (self._labelled("Tema", self.theme_combo),
                       self.notifications_check, self.close_check):
            appearance.body.addWidget(widget)
        appearance.body.addWidget(FieldRow(
            "Critérios",
            "Erros e avisos aparecem mesmo com as notificações não críticas desligadas; "
            "a confirmação de fechamento protege operações em andamento."))
        body.addWidget(appearance)

        performance = Card(padding=16, spacing=10)
        performance.body.addWidget(SectionHeader("Desempenho da varredura"))
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 8)
        self.workers_spin.setToolTip(
            "Threads de análise usadas por Scanner ao iniciar uma varredura (1–8).")
        self.cpu_spin = QSpinBox()
        self.cpu_spin.setRange(10, 100)
        self.cpu_spin.setSuffix(" %")
        self.cpu_spin.setToolTip(
            "Limite de uso de CPU aplicado pelo núcleo quando psutil está disponível.")
        performance.body.addWidget(self._labelled("Threads de análise", self.workers_spin))
        performance.body.addWidget(self._labelled("Limite de CPU", self.cpu_spin))
        performance.body.addWidget(FieldRow(
            "Aplicação",
            "Valores lidos do núcleo: Scanner(workers=..., cpu_limit=...). "
            "A alteração vale para as próximas varreduras; não altera a varredura em andamento."))
        body.addWidget(performance)

        folders = Card(padding=16, spacing=10)
        folders.body.addWidget(SectionHeader("Pastas da varredura personalizada"))
        folders.body.addWidget(FieldRow(
            "Efeito", "Lista usada como destino da varredura personalizada na tela Scanner."))
        self.folder_input = QLineEdit()
        self.folder_input.setPlaceholderText("Caminho da pasta…")
        add_folder = make_button("Adicionar pasta", "folder", clicked=self.add_folder)
        pick_folder = make_button("Selecionar…", "search", clicked=self.pick_folder)
        line = QHBoxLayout()
        line.setSpacing(8)
        line.addWidget(self.folder_input, 1)
        line.addWidget(add_folder)
        line.addWidget(pick_folder)
        folders.body.addLayout(line)
        self.folder_list = QListWidget()
        self.folder_list.setMinimumHeight(90)
        folders.body.addWidget(self.folder_list)
        folders.body.addWidget(make_button(
            "Remover pasta selecionada", "trash", clicked=lambda: self.remove_selected("scan_directories")))
        body.addWidget(folders)

        exclusions = Card(padding=16, spacing=10)
        exclusions.body.addWidget(SectionHeader("Exclusões da varredura local"))
        exclusions.body.addWidget(FieldRow(
            "Efeito",
            "Caminhos ignorados pelo Scanner.run(..., exclude_paths=...). "
            "NÃO são exclusões do Windows Defender e não alteram o sistema."))
        self.exclusion_input = QLineEdit()
        self.exclusion_input.setPlaceholderText("Arquivo ou pasta existente…")
        add_exclusion = make_button("Adicionar caminho", "check", clicked=self.add_exclusion)
        pick_exclusion = make_button("Selecionar pasta…", "folder", clicked=self.pick_exclusion)
        line = QHBoxLayout()
        line.setSpacing(8)
        line.addWidget(self.exclusion_input, 1)
        line.addWidget(add_exclusion)
        line.addWidget(pick_exclusion)
        exclusions.body.addLayout(line)
        self.exclusion_list = QListWidget()
        self.exclusion_list.setMinimumHeight(90)
        exclusions.body.addWidget(self.exclusion_list)
        exclusions.body.addWidget(make_button(
            "Remover exclusão selecionada", "trash",
            clicked=lambda: self.remove_selected("exclusions")))
        body.addWidget(exclusions)

        logging_card = Card(padding=16, spacing=10)
        logging_card.body.addWidget(SectionHeader("Registro de atividades"))
        self.log_combo = QComboBox()
        for level in LOG_LEVELS:
            self.log_combo.addItem(level)
        logging_card.body.addWidget(self._labelled("Nível de log", self.log_combo))
        logging_card.body.addWidget(FieldRow(
            "Arquivo", str(config.LOG_DIR / "sentinel.log")))
        logging_card.body.addWidget(FieldRow(
            "Efeito", "Aplicado ao logger 'sentinel' imediatamente após salvar."))
        body.addWidget(logging_card)

        note = QLabel(
            "Esta tela não altera proteções, serviços, tarefas, Registro nem o Microsoft Defender. "
            "O idioma da interface é fixo em português: nenhuma opção sem efeito real é exibida. "
            "Valores inválidos ou fora dos limites são ajustados pelo próprio arquivo de "
            "preferências quando carregados.")
        set_role(note, "muted2")
        note.setWordWrap(True)
        body.addWidget(note)
        body.addWidget(Separator())
        body.addStretch(1)
        root.addWidget(make_scroll(content))
        _connect_changes(self)
        self._load()

    @staticmethod
    def _labelled(label: str, widget: QWidget) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        caption = QLabel(label)
        set_role(caption, "muted2")
        caption.setMinimumWidth(150)
        layout.addWidget(caption)
        layout.addWidget(widget, 1)
        return container

    # ------------------------------------------------------------------ dados
    def on_activate(self) -> None:
        super().on_activate()
        if not self._dirty:
            self._load()

    def _load(self) -> None:
        self._loading = True
        try:
            settings = self.context.settings
            theme = str(settings.get("theme", "dark"))
            index = next((i for i, (_label, value) in enumerate(THEMES) if value == theme), 0)
            self.theme_combo.setCurrentIndex(index)
            self.notifications_check.setChecked(bool(settings.get("notifications", True)))
            self.close_check.setChecked(bool(settings.get("confirm_close_during_scan", True)))
            self.workers_spin.setValue(int(settings.get("scan_workers", 2)))
            self.cpu_spin.setValue(int(settings.get("cpu_limit", 60)))
            level = str(settings.get("log_level", "INFO"))
            self.log_combo.setCurrentIndex(LOG_LEVELS.index(level) if level in LOG_LEVELS else 1)
            self._set_list(self.folder_list, settings.get("scan_directories", []))
            self._set_list(self.exclusion_list, settings.get("exclusions", []))
        finally:
            self._loading = False
        self._dirty = False
        self.status_badge.setText("Sem alterações")
        self.status_badge.set_level("gray")
        self.footer_label.setText(
            f"Preferências carregadas de {settings.path} às {format_time(datetime.now())}.")

    @staticmethod
    def _set_list(widget: QListWidget, values) -> None:
        widget.clear()
        for value in values:
            text = str(value).strip()
            if text:
                widget.addItem(text)

    def _collect(self) -> dict:
        theme = THEMES[self.theme_combo.currentIndex()][1] \
            if 0 <= self.theme_combo.currentIndex() < len(THEMES) else "dark"
        return {
            "theme": theme,
            "notifications": self.notifications_check.isChecked(),
            "confirm_close_during_scan": self.close_check.isChecked(),
            "scan_workers": self.workers_spin.value(),
            "cpu_limit": self.cpu_spin.value(),
            "log_level": self.log_combo.currentText(),
            "scan_directories": [self.folder_list.item(i).text()
                                 for i in range(self.folder_list.count())],
            "exclusions": [self.exclusion_list.item(i).text()
                           for i in range(self.exclusion_list.count())],
        }

    def _mark_dirty(self, *_args) -> None:
        if self._loading:
            return
        self._dirty = True
        self.status_badge.setText("Alterações pendentes")
        self.status_badge.set_level("warning")
        self.status_label.setText("Salve para aplicar tema e nível de log e gravar as listas.")

    # ------------------------------------------------------------------ ações
    def save(self) -> None:
        values = self._collect()
        changed = [key for key, value in values.items()
                   if self.context.settings.get(key) != value]
        try:
            self.context.settings.update(values)
            self.context.settings.save()
        except OSError as exc:
            self.error("Não foi possível salvar as preferências", friendly_error(exc))
            self.banner.set_message("danger", "Falha ao salvar", friendly_error(exc))
            return
        self._dirty = False
        self.status_badge.setText("Salvo")
        self.status_badge.set_level("safe")
        self.status_label.setText(
            "Preferências gravadas; tema e nível de log aplicados nesta sessão.")
        self.footer_label.setText(
            f"Última gravação: {format_time(datetime.now())}  •  {self.context.settings.path}")
        if changed:
            self.emit_settings_changed(changed)
            self.banner.set_message(
                "success", "Preferências salvas",
                "Aplicadas agora: " + ", ".join(changed) +
                ". Pastas e exclusões entram na próxima varredura.")
        else:
            self.banner.set_message("info", "Nenhuma alteração",
                                    "As preferências já estavam gravadas com esses valores.")
        self.info("Configurações salvas", ", ".join(changed) or "nenhuma alteração")

    def reload(self) -> None:
        if self._dirty and not self.confirm(
            "Descartar alterações não salvas",
            "As edições pendentes nesta tela serão substituídas pelo arquivo de preferências.",
            danger=True, confirm_text="Recarregar arquivo",
        ):
            return
        self.context.settings.load()
        self._load()
        self.emit_settings_changed(list(self.context.settings.as_dict()))
        self.banner.set_message("info", "Preferências recarregadas",
                                "Tema e nível de log foram reaplicados.")

    def reset_defaults(self) -> None:
        if not self.confirm(
            "Restaurar preferências padrão",
            "Tema, notificações, desempenho, pastas, exclusões e nível de log voltarão "
            "aos valores iniciais. Nenhum arquivo do sistema será alterado.",
            "Exclusões e pastas personalizadas serão removidas do arquivo de preferências.",
            danger=True, confirm_text="Restaurar padrões", require_ack=True,
            ack_text="Entendo que minhas preferências serão substituídas.",
        ):
            return
        self.context.settings.reset()
        self._load()
        self.emit_settings_changed(list(self.context.settings.as_dict()))
        self.banner.set_message("warning", "Preferências restauradas",
                                "Tema e nível de log foram reaplicados aos valores padrão.")

    def _normalized_path(self, raw: str, *, directory_only: bool = False) -> Path | None:
        text = str(raw or "").strip()
        if not text:
            return None
        try:
            path = Path(text).expanduser().resolve()
        except OSError:
            return None
        valid = path.is_dir() if directory_only else path.exists()
        if not valid:
            self.warn("Caminho inválido",
                      "Informe um caminho existente; o valor não foi adicionado.")
            return None
        return path

    def add_folder(self) -> None:
        path = self._normalized_path(self.folder_input.text(), directory_only=True)
        if path is None:
            return
        self._add_to(self.folder_list, str(path))

    def pick_folder(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Pasta da varredura personalizada")
        if chosen:
            self.folder_input.setText(chosen)
            self.add_folder()

    def add_exclusion(self) -> None:
        path = self._normalized_path(self.exclusion_input.text())
        if path is None:
            return
        self._add_to(self.exclusion_list, str(path))

    def pick_exclusion(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Pasta a excluir da varredura")
        if chosen:
            self.exclusion_input.setText(chosen)
            self.add_exclusion()

    def _add_to(self, widget: QListWidget, text: str) -> None:
        existing = {widget.item(i).text() for i in range(widget.count())}
        if text in existing:
            self.info("Já adicionado", text)
            return
        widget.addItem(text)
        self._mark_dirty()

    def remove_selected(self, key: str) -> None:
        widget = self.folder_list if key == "scan_directories" else self.exclusion_list
        row = widget.currentRow()
        if row >= 0:
            widget.takeItem(row)
            self._mark_dirty()


def _connect_changes(view: SettingsView) -> None:
    """Liga os controles após a construção (evita sinais durante `_load`)."""
    view.theme_combo.currentIndexChanged.connect(view._mark_dirty)
    view.notifications_check.toggled.connect(view._mark_dirty)
    view.close_check.toggled.connect(view._mark_dirty)
    view.workers_spin.valueChanged.connect(view._mark_dirty)
    view.cpu_spin.valueChanged.connect(view._mark_dirty)
    view.log_combo.currentIndexChanged.connect(view._mark_dirty)
