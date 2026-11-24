"""Inicialização única da interface gráfica do Sentinel Scanner."""
from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication, QMessageBox

from core import config
from core.logger import get_logger, set_level, setup_logging
from .components.icons import logo_icon
from .context import AppContext
from .main_window import MainWindow
from .settings import Settings
from .styles.theme import stylesheet

log = get_logger("gui.app")


def _configure_qt_environment() -> None:
    try:
        QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    except (AttributeError, RuntimeError):
        pass


def create_application(argv: list[str] | None = None) -> QApplication:
    _configure_qt_environment()
    app = QApplication.instance()
    if app is None:
        app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName(config.APP_NAME)
    app.setApplicationVersion(config.APP_VERSION)
    app.setOrganizationName("Sentinel Scanner")
    app.setStyle("Fusion")
    app.setWindowIcon(logo_icon(64))
    return app


def main(argv: list[str] | None = None) -> int:
    config.ensure_dirs()
    setup_logging()
    app = None
    context: AppContext | None = None
    window: MainWindow | None = None
    try:
        app = create_application(argv)
        settings = Settings()
        set_level(str(settings.get("log_level", "INFO")))
        app.setStyleSheet(stylesheet(str(settings.get("theme", "dark"))))
        context = AppContext(settings=settings)
        window = MainWindow(context)
        window.show()
        return app.exec()
    except Exception as exc:
        log.exception("Falha ao iniciar a interface")
        message = f"Não foi possível iniciar o Sentinel Scanner.\n\n{exc}"
        if app is not None:
            try:
                QMessageBox.critical(None, config.APP_NAME, message)
            except Exception:
                print(message, file=sys.stderr)
        else:
            print(message, file=sys.stderr)
        return 1
    finally:
        if window is not None:
            try:
                window.prepare_close(force=True)
            except Exception:
                log.exception("Falha ao encerrar a janela principal")
        if context is not None:
            context.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
