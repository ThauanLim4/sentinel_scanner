"""Contexto da aplicação: banco, quarentena, configurações e fábricas do núcleo.

As telas nunca criam analisadores diretamente: elas pedem ao contexto. Isso mantém um
único ponto de integração e facilita substituir serviços por dublês nos testes.
"""
from __future__ import annotations

from pathlib import Path

from core import cleanup, config
from core.defender import DefenderClient
from core.logger import get_logger
from core.network_analyzer import NetworkAnalyzer
from core.process_analyzer import ProcessAnalyzer
from core.quarantine import Quarantine
from core.scanner import Scanner
from core.startup_analyzer import StartupAnalyzer, StartupManager
from database.database import Database

from .settings import Settings


class AppContext:
    def __init__(self, settings: Settings | None = None, db_path: Path | str | None = None,
                 quarantine_dir: Path | str | None = None):
        self.log = get_logger("gui")
        self.settings = settings or Settings()
        self._db_path = Path(db_path) if db_path else None
        self._quarantine_dir = Path(quarantine_dir) if quarantine_dir else None
        self._db: Database | None = None
        self.db_error: Exception | None = None
        self._quarantine: Quarantine | None = None
        self.quarantine_error: Exception | None = None
        self._overrides: dict[str, object] = {}
        self._network: NetworkAnalyzer | None = None
        self._processes: ProcessAnalyzer | None = None
        self._defender: DefenderClient | None = None
        self._startup_manager: StartupManager | None = None
        self._closed = False
        self._open_database()

    # ------------------------------------------------------------------ serviços
    def _open_database(self) -> None:
        try:
            config.ensure_dirs()
            self._db = Database(self._db_path)
        except Exception as exc:  # banco quebrado não deve impedir a interface de abrir
            self._db = None
            self.db_error = exc
            self.log.exception("Falha ao abrir o banco de dados")

    @property
    def db(self) -> Database | None:
        return self._db

    @property
    def quarantine(self) -> Quarantine | None:
        override = self._override("quarantine")
        if override is not None:
            return override
        if self._quarantine is None and self.quarantine_error is None and self._db is not None:
            try:
                self._quarantine = Quarantine(self._db, self._quarantine_dir)
            except Exception as exc:
                self.quarantine_error = exc
                self.log.exception("Falha ao inicializar a quarentena")
        return self._quarantine

    def set_override(self, name: str, value) -> None:
        """Substitui um serviço do núcleo (usado pelos testes de interface)."""
        self._overrides[name] = value

    def _override(self, name: str):
        return self._overrides.get(name)

    def defender_client(self) -> DefenderClient:
        override = self._override("defender")
        if override is not None:
            return override
        if self._defender is None:
            self._defender = DefenderClient()
        return self._defender

    def process_analyzer(self) -> ProcessAnalyzer:
        override = self._override("processes")
        if override is not None:
            return override
        if self._processes is None:
            self._processes = ProcessAnalyzer(db=self._db)
        return self._processes

    def network_analyzer(self) -> NetworkAnalyzer:
        override = self._override("network")
        if override is not None:
            return override
        if self._network is None:
            self._network = NetworkAnalyzer()
        return self._network

    def make_startup_analyzer(self) -> StartupAnalyzer:
        override = self._override("startup")
        if override is not None:
            return override
        return StartupAnalyzer(db=self._db)

    def startup_manager(self) -> StartupManager:
        """Gerenciador de inicialização reutiliza o acesso ao Registro do analisador."""
        override = self._override("startup_manager")
        if override is not None:
            return override
        if self._startup_manager is None:
            access = getattr(self.make_startup_analyzer(), "access", None)
            if access is not None:
                self._startup_manager = StartupManager(access=access, db=self._db)
            else:
                self._startup_manager = StartupManager(db=self._db)
        return self._startup_manager

    def make_cleanup_categories(self) -> list:
        """Categorias definidas pelo núcleo; a tela não inventa raízes nem padrões."""
        override = self._override("cleanup_categories")
        if override is not None:
            return override() if callable(override) else override
        return cleanup.build_categories()

    def make_scanner(self, workers: int | None = None, cpu_limit: int | None = None) -> Scanner:
        override = self._override("scanner")
        if override is not None:
            return override() if callable(override) else override
        if self._db is None:
            raise RuntimeError("Banco de dados indisponível; a varredura não pode ser registrada.")
        return Scanner(self._db, workers=workers or self.settings.get("scan_workers", 2),
                       cpu_limit=cpu_limit if cpu_limit is not None else self.settings.get("cpu_limit", 60))

    # ------------------------------------------------------------------ ciclo de vida
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._db is not None:
            try:
                self._db.close()
            except Exception:
                self.log.exception("Falha ao fechar o banco de dados")
            self._db = None
        self._quarantine = None
        self._startup_manager = None
