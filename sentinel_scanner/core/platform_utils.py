"""Utilitários de integração com o Windows (PowerShell) e checagens de plataforma."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from typing import Any

IS_WINDOWS = sys.platform == "win32"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


class PowerShellError(RuntimeError):
    pass


def powershell_exe() -> str:
    return shutil.which("powershell.exe") or "powershell.exe"


def run_powershell(script: str, stdin_text: str | None = None, timeout: int = 60,
                   env: dict | None = None) -> subprocess.CompletedProcess:
    """Executa um script PowerShell sem alterar a política de execução.
    Dados variáveis (caminhos etc.) devem ir por stdin ou variáveis de ambiente,
    nunca concatenados no script (evita injeção de comandos)."""
    if not IS_WINDOWS:
        raise PowerShellError("PowerShell só está disponível no Windows.")
    return subprocess.run(
        [powershell_exe(), "-NoProfile", "-NonInteractive", "-Command", script],
        input=stdin_text, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout, env=env, creationflags=CREATE_NO_WINDOW,
    )


def run_powershell_json(script: str, stdin_text: str | None = None, timeout: int = 60) -> Any:
    proc = run_powershell(script, stdin_text, timeout)
    out = (proc.stdout or "").strip()
    if proc.returncode != 0 and not out:
        raise PowerShellError((proc.stderr or "erro desconhecido").strip())
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise PowerShellError(f"Saída JSON inválida: {exc}") from exc
