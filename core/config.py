"""Configuração central: caminhos, versão e listas usadas pelas heurísticas."""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "Sentinel Scanner"
APP_VERSION = "0.1.0"


def _default_home() -> Path:
    if os.environ.get("SENTINEL_HOME"):
        return Path(os.environ["SENTINEL_HOME"])
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


HOME = _default_home()
LOG_DIR = HOME / "logs"
QUARANTINE_DIR = HOME / "quarantine"
REPORTS_DIR = HOME / "reports"
DATA_DIR = HOME / "data"
SIGNATURES_DIR = DATA_DIR / "signatures"  # listas locais de hashes SHA-256 (um por linha)
DB_PATH = DATA_DIR / "sentinel.db"


def ensure_dirs() -> None:
    for d in (LOG_DIR, QUARANTINE_DIR, REPORTS_DIR, DATA_DIR, SIGNATURES_DIR):
        d.mkdir(parents=True, exist_ok=True)


EXECUTABLE_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".msi"}
SCRIPT_EXT = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd", ".hta"}
DOCUMENT_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".odt",
}

# Extensões que a limpeza automática NUNCA deve apagar, mesmo dentro de diretórios
# temporários: documentos, mídia, arquivos compactados e fontes de projetos.
PERSONAL_EXT = DOCUMENT_EXT | {
    ".wav", ".flac", ".aac", ".ogg", ".m4a", ".mkv", ".mov", ".wmv", ".webm",
    ".tif", ".tiff", ".webp", ".heic", ".svg", ".psd", ".raw",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".py", ".pyw", ".js", ".ts", ".tsx", ".jsx", ".java", ".cs", ".cpp", ".c", ".h", ".hpp",
    ".go", ".rs", ".rb", ".php", ".html", ".htm", ".css", ".scss", ".json", ".xml",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".md", ".rst", ".sql", ".db", ".sqlite",
}

# Nomes de processos do Windows frequentemente imitados por malware.
SYSTEM_PROCESS_NAMES = {
    "svchost.exe", "explorer.exe", "csrss.exe", "lsass.exe", "winlogon.exe",
    "services.exe", "taskhostw.exe", "smss.exe", "wininit.exe", "dllhost.exe",
    "conhost.exe", "spoolsv.exe", "runtimebroker.exe", "sihost.exe", "ctfmon.exe",
    "searchindexer.exe", "fontdrvhost.exe",
}

# Diretórios ignorados na varredura (protegidos, enormes ou sem valor para análise).
SCAN_EXCLUDED_DIR_NAMES = {
    "$recycle.bin", "system volume information", "winsxs", "$windows.~bt",
    "$windows.~ws", "windowsapps", "servicing", "installer",
}

MAX_STRING_SCAN_BYTES = 8 * 1024 * 1024
MAX_SCRIPT_SCAN_BYTES = 512 * 1024
RECENT_FILE_DAYS = 7
