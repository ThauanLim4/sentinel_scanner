"""Integração com o Microsoft Defender via cmdlets oficiais (Get-MpComputerStatus, Start-MpScan,
Update-MpSignature, Get-MpThreat...) e MpCmdRun.exe. Nunca desativa ou altera configurações do Defender."""
from __future__ import annotations

import glob
import os
import subprocess
from pathlib import Path

from .logger import get_logger
from .platform_utils import CREATE_NO_WINDOW, IS_WINDOWS, PowerShellError, powershell_exe, run_powershell_json

log = get_logger(__name__)

_DT = "if($v){$v.ToString('o')}else{''}"
_PS_STATUS = f"""
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$s=Get-MpComputerStatus
function D($v){{ {_DT} }}
[pscustomobject]@{{
 ServiceEnabled=[bool]$s.AMServiceEnabled; AntivirusEnabled=[bool]$s.AntivirusEnabled
 RealTime=[bool]$s.RealTimeProtectionEnabled; TamperProtected=[bool]$s.IsTamperProtected
 SignatureVersion=[string]$s.AntivirusSignatureVersion; SignatureUpdated=(D $s.AntivirusSignatureLastUpdated)
 SignatureAgeDays=[int]$s.AntivirusSignatureAge; QuickScanEnd=(D $s.QuickScanEndTime); FullScanEnd=(D $s.FullScanEndTime)
}} | ConvertTo-Json -Compress
"""
_PS_PRODUCTS = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
                "ConvertTo-Json -InputObject @(Get-CimInstance -Namespace root/SecurityCenter2 "
                "-ClassName AntivirusProduct | Select-Object displayName,productState) -Compress")
_PS_THREATS = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
               "ConvertTo-Json -InputObject @(Get-MpThreat | Select-Object ThreatID,ThreatName,SeverityID,"
               "IsActive,@{n='Resources';e={@($_.Resources)}}) -Compress -Depth 3")
_PS_HISTORY = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
               "ConvertTo-Json -InputObject @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending "
               "| Select-Object -First 200 ThreatID,ProcessName,ActionSuccess,CurrentThreatExecutionStatusID,"
               "@{n='Time';e={if($_.InitialDetectionTime){$_.InitialDetectionTime.ToString('o')}}},"
               "@{n='Resources';e={@($_.Resources)}}) -Compress -Depth 3")


def mpcmdrun_path() -> Path | None:
    candidates = sorted(glob.glob(os.path.expandvars(
        r"%ProgramData%\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe")), reverse=True)
    candidates.append(os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe"))
    for c in candidates:
        if Path(c).exists():
            return Path(c)
    return None


def _as_list(x):
    return [] if x is None else (x if isinstance(x, list) else [x])


class DefenderUnavailable(Exception):
    pass


class DefenderClient:
    def status(self) -> dict:
        """Estado do Defender. Se outro antivírus estiver ativo ou o Defender estiver desativado,
        o retorno informa isso explicitamente em 'available'/'message'."""
        if not IS_WINDOWS:
            return {"available": False, "message": "Disponível apenas no Windows.", "products": []}
        out: dict = {"available": False, "products": []}
        try:
            out["products"] = [p["displayName"] for p in _as_list(run_powershell_json(_PS_PRODUCTS))]
        except PowerShellError as exc:
            log.warning("Security Center indisponível: %s", exc)
        try:
            data = run_powershell_json(_PS_STATUS)
            if data:
                out.update(data)
                out["available"] = bool(data.get("ServiceEnabled"))
                if not data.get("AntivirusEnabled"):
                    out["message"] = "Microsoft Defender instalado, mas com antivírus desativado (possível outro antivírus ativo)."
                elif not data.get("RealTime"):
                    out["message"] = "Proteção em tempo real DESATIVADA."
                elif data.get("SignatureAgeDays", 0) > 3:
                    out["message"] = "Definições de vírus desatualizadas."
        except PowerShellError as exc:
            out["message"] = f"Defender indisponível: {exc}"
        return out

    def update_signatures(self) -> bool:
        run_powershell_json("Update-MpSignature; '{\"ok\":true}'", timeout=600)
        return True

    def threats(self) -> list[dict]:
        return _as_list(run_powershell_json(_PS_THREATS))

    def history(self) -> list[dict]:
        return _as_list(run_powershell_json(_PS_HISTORY))

    def quarantined_items(self) -> str:
        exe = mpcmdrun_path()
        if not exe:
            raise DefenderUnavailable("MpCmdRun.exe não encontrado.")
        proc = subprocess.run([str(exe), "-Restore", "-ListAll"], capture_output=True, text=True,
                              errors="replace", timeout=60, creationflags=CREATE_NO_WINDOW)
        return proc.stdout.strip()

    def start_scan(self, kind: str = "quick", path: str | None = None) -> "DefenderScan":
        if kind not in ("quick", "full", "custom"):
            raise ValueError("kind inválido")
        if kind == "custom" and not (path and Path(path).exists()):
            raise ValueError("Informe um caminho existente para a verificação personalizada.")
        return DefenderScan(kind, path)

    def exclusions(self) -> dict:
        """Exclusões configuradas no Defender. Sem administrador o Windows devolve 'N/A: ...';
        nesse caso 'restricted' vem True e as listas vazias."""
        data = run_powershell_json(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$p=Get-MpPreference;"
            "[pscustomobject]@{Paths=@($p.ExclusionPath);Processes=@($p.ExclusionProcess);"
            "Extensions=@($p.ExclusionExtension)}|ConvertTo-Json -Compress") or {}
        out: dict = {"restricted": False}
        for key in ("Paths", "Processes", "Extensions"):
            items = [str(x) for x in _as_list(data.get(key)) if x]
            if any(i.startswith("N/A") for i in items):
                out["restricted"], items = True, []
            out[key] = items
        return out


class DefenderScan:
    """Verificação executada em processo separado; pode ser cancelada. O caminho vai por variável
    de ambiente (nunca interpolado no script)."""

    def __init__(self, kind: str, path: str | None):
        self.kind, self.path = kind, path
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        if not IS_WINDOWS:
            raise DefenderUnavailable("Disponível apenas no Windows.")
        scan_type = {"quick": "QuickScan", "full": "FullScan", "custom": "CustomScan"}[self.kind]
        script = (f"Start-MpScan -ScanType {scan_type}" +
                  (" -ScanPath $env:SENTINEL_SCANPATH" if self.kind == "custom" else ""))
        env = dict(os.environ, SENTINEL_SCANPATH=self.path or "")
        self.proc = subprocess.Popen([powershell_exe(), "-NoProfile", "-NonInteractive", "-Command", script],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     errors="replace", env=env, creationflags=CREATE_NO_WINDOW)

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def wait(self, timeout: float | None = None) -> tuple[int, str]:
        assert self.proc
        out, err = self.proc.communicate(timeout=timeout)
        return self.proc.returncode, (err or out or "").strip()

    def cancel(self) -> None:
        exe = mpcmdrun_path()
        if exe:
            subprocess.run([str(exe), "-Cancel"], capture_output=True, timeout=30, creationflags=CREATE_NO_WINDOW)
        if self.running():
            self.proc.terminate()  # type: ignore[union-attr]
