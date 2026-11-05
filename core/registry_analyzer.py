"""Análise do Registro do Windows (somente leitura por padrão).

- RegistryAccess: acesso real via winreg. FakeRegistry: mesma API em memória (testes).
- RegistryAnalyzer: procura alterações típicas de malware (Winlogon, IFEO, AppInit, sequestro de
  associações, políticas que desativam Defender/UAC/Firewall, proxy, políticas de navegador,
  exclusões do Defender). Cada achado é uma Evidence com peso; NADA é modificado na análise.
- RegistryFixer: correções pontuais e reversíveis, SOMENTE de itens da lista de permissões,
  com confirmação e backup .reg da chave antes de qualquer escrita."""
from __future__ import annotations

import json
import ntpath
import os
import re
import subprocess
import time
from pathlib import Path

from . import config
from .file_analyzer import expand_env, in_temp_dir, in_user_writable_dir
from .logger import get_logger
from .models import Finding
from .platform_utils import CREATE_NO_WINDOW, IS_WINDOWS
from .safety import norm

try:
    import winreg  # type: ignore
except ImportError:  # fora do Windows o módulo continua importável
    winreg = None

log = get_logger(__name__)
HKLM, HKCU = "HKLM", "HKCU"
_ROOT_NAMES = {HKLM: "HKEY_LOCAL_MACHINE", HKCU: "HKEY_CURRENT_USER"}


class RegistryError(Exception):
    pass


# ------------------------------------------------------------------------- acesso ao Registro
class RegistryAccess:
    def __init__(self):
        if winreg is None:
            raise RegistryError("winreg indisponível: o Registro só pode ser lido no Windows.")
        self._h = {HKLM: winreg.HKEY_LOCAL_MACHINE, HKCU: winreg.HKEY_CURRENT_USER}

    def _open(self, hive: str, path: str, write: bool = False):
        return winreg.OpenKey(self._h[hive], path, 0, winreg.KEY_SET_VALUE if write else winreg.KEY_READ)

    def key_exists(self, hive: str, path: str) -> bool:
        try:
            winreg.CloseKey(self._open(hive, path))
            return True
        except OSError:
            return False

    def values(self, hive: str, path: str) -> dict:
        out: dict = {}
        try:
            key = self._open(hive, path)
        except OSError:
            return out
        with key:
            i = 0
            while True:
                try:
                    name, data, typ = winreg.EnumValue(key, i)
                except OSError:
                    break
                out[name] = (data, typ)
                i += 1
        return out

    def subkeys(self, hive: str, path: str) -> list[str]:
        out: list[str] = []
        try:
            key = self._open(hive, path)
        except OSError:
            return out
        with key:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
        return out

    def get(self, hive: str, path: str, name: str):
        try:
            with self._open(hive, path) as key:
                return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    def set_value(self, hive: str, path: str, name: str, data, typ: str = "REG_SZ") -> None:
        try:
            with winreg.CreateKeyEx(self._h[hive], path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, name, 0, getattr(winreg, typ), data)
        except PermissionError as exc:
            raise RegistryError("Permissão negada: execute o programa como administrador.") from exc

    def delete_value(self, hive: str, path: str, name: str) -> None:
        try:
            with self._open(hive, path, write=True) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass
        except PermissionError as exc:
            raise RegistryError("Permissão negada: execute o programa como administrador.") from exc


class FakeRegistry:
    """Registro em memória com a mesma API (para testes e simulações controladas)."""

    def __init__(self, data: dict | None = None):
        self.data: dict = {}
        for (hive, path), vals in (data or {}).items():
            self.data[(hive, path.lower())] = {n: (v if isinstance(v, tuple) else (v, 1)) for n, v in vals.items()}

    def key_exists(self, hive, path):
        p = path.lower()
        return (hive, p) in self.data or any(h == hive and k.startswith(p + "\\") for h, k in self.data)

    def values(self, hive, path):
        return dict(self.data.get((hive, path.lower()), {}))

    def subkeys(self, hive, path):
        prefix = path.lower() + "\\"
        return sorted({k[len(prefix):].split("\\")[0] for h, k in self.data if h == hive and k.startswith(prefix)})

    def get(self, hive, path, name):
        for n, (d, _t) in self.values(hive, path).items():
            if n.lower() == name.lower():
                return d
        return None

    def set_value(self, hive, path, name, data, typ="REG_SZ"):
        self.data.setdefault((hive, path.lower()), {})[name] = (data, typ)

    def delete_value(self, hive, path, name):
        vals = self.data.get((hive, path.lower()), {})
        for n in list(vals):
            if n.lower() == name.lower():
                del vals[n]


def backup_key(hive: str, path: str, directory=None) -> Path:
    """Exporta a chave para um .reg (restaurável com duplo clique ou 'reg import')."""
    if not IS_WINDOWS:
        raise RegistryError("Backup do Registro só está disponível no Windows.")
    d = Path(directory or config.DATA_DIR / "backups" / "registry")
    d.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{hive}_{path}")[-120:]
    out = d / f"{time.strftime('%Y%m%d_%H%M%S')}_{safe}.reg"
    proc = subprocess.run(["reg.exe", "export", f"{_ROOT_NAMES[hive]}\\{path}", str(out), "/y"],
                          capture_output=True, text=True, errors="replace", timeout=60,
                          creationflags=CREATE_NO_WINDOW)
    if proc.returncode != 0 or not out.exists():
        raise RegistryError(f"Falha ao exportar backup de {hive}\\{path}: {(proc.stderr or proc.stdout).strip()}")
    return out


# ------------------------------------------------------------------------- regras de análise
WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
WINDOWS_NT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
USER_SHELL = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
INET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
ACCESSIBILITY = {"sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe"}
UAC_BYPASS_HANDLERS = ("ms-settings", "mscfile", "exefile", "folder", "wsreset")
CLASS_COMMANDS = ("exefile", "comfile", "batfile", "cmdfile")
BROWSER_POLICIES = (
    ("Google Chrome", r"SOFTWARE\Policies\Google\Chrome"),
    ("Microsoft Edge", r"SOFTWARE\Policies\Microsoft\Edge"),
    ("Mozilla Firefox", r"SOFTWARE\Policies\Mozilla\Firefox"),
)
BROWSER_SENSITIVE = {n.lower() for n in (
    "ExtensionInstallForcelist", "HomepageLocation", "RestoreOnStartupURLs", "DefaultSearchProviderSearchURL",
    "DefaultSearchProviderName", "ProxyServer", "ProxySettings", "ExtensionInstallSources", "NewTabPageLocation",
    "Homepage", "Extensions", "SearchEngines", "Proxy")}
RISKY_EXCLUDED_EXT = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", "exe", "dll", "ps1", "bat", "cmd", "vbs", "js"}

# (hive, chave, valor, valores_ruins, código, descrição, peso, correção)
POLICY_CHECKS = [
    (HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", (1,), "pol_def_off",
     "Política desativa o Microsoft Defender (alguns antivírus de terceiros também definem isso)", 30, "delete"),
    (HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiVirus", (1,), "pol_def_av_off",
     "Política desativa o antivírus do Defender", 30, "delete"),
    (HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", (1,),
     "pol_def_rt_off", "Política desativa a proteção em tempo real do Defender", 30, "delete"),
    (HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", (1,),
     "pol_def_beh_off", "Política desativa o monitoramento comportamental do Defender", 30, "delete"),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", (0,), "pol_uac_off",
     "UAC (controle de conta de usuário) desativado", 40, ("set", 1, "REG_DWORD")),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", (0,),
     "pol_uac_silent", "Elevação de administrador sem nenhum aviso (UAC silencioso)", 25, ("set", 5, "REG_DWORD")),
    (HKCU, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", (1,), "pol_taskmgr",
     "Gerenciador de Tarefas bloqueado por política", 25, "delete"),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", (1,), "pol_taskmgr_m",
     "Gerenciador de Tarefas bloqueado por política", 25, "delete"),
    (HKCU, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", (1,), "pol_regedit",
     "Editor do Registro bloqueado por política", 25, "delete"),
    (HKCU, r"Software\Policies\Microsoft\Windows\System", "DisableCMD", (1, 2), "pol_cmd",
     "Prompt de comando bloqueado por política", 20, "delete"),
    (HKLM, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
     "EnableFirewall", (0,), "pol_fw_std", "Firewall desativado (perfil padrão)", 20, ("set", 1, "REG_DWORD")),
    (HKLM, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
     "EnableFirewall", (0,), "pol_fw_pub", "Firewall desativado (perfil público)", 20, ("set", 1, "REG_DWORD")),
    (HKLM, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
     "EnableFirewall", (0,), "pol_fw_dom", "Firewall desativado (perfil de domínio)", 20, ("set", 1, "REG_DWORD")),
]


def _fix_spec(hive, key, value, how):
    if how == "delete":
        return {"action": "delete_value", "hive": hive, "key": key, "value": value}
    return {"action": "set_value", "hive": hive, "key": key, "value": value, "data": how[1], "type": how[2]}


def _is_allowed_fix(fix: dict) -> bool:
    """Lista de permissões: só alvos que o próprio analisador sabe corrigir."""
    h, k, v = fix.get("hive"), str(fix.get("key", "")).lower(), str(fix.get("value", "")).lower()
    for ph, pk, pv, *_ in POLICY_CHECKS:
        if (h, k, v) == (ph, pk.lower(), pv.lower()):
            return True
    fixed = {(HKLM, WINLOGON.lower(), "shell"), (HKLM, WINLOGON.lower(), "userinit"),
             (HKCU, INET.lower(), "proxyenable"), (HKCU, INET.lower(), "autoconfigurl"),
             (HKCU, USER_SHELL.lower(), "startup"), (HKLM, WINDOWS_NT.lower(), "appinit_dlls"),
             (HKLM, r"software\classes\.exe", "")}
    if (h, k, v) in fixed:
        return True
    if h == HKLM and k.startswith(IFEO.lower() + "\\") and v == "debugger":
        return True
    return h == HKLM and v == "" and any(k == rf"software\classes\{c}\shell\open\command" for c in CLASS_COMMANDS)


class RegistryAnalyzer:
    def __init__(self, access=None, defender=None):
        self.a = access if access is not None else RegistryAccess()
        self.defender = defender

    def _finding(self, hive, key, value, code, desc, weight, category, data=None, fix=None) -> Finding:
        f = Finding(path=f"{hive}\\{key}\\{value}" if value else f"{hive}\\{key}", category=category)
        f.add(code, desc, weight, category)
        f.extra = {"kind": "registry", "hive": hive, "key": key, "value": value,
                   "data": "" if data is None else str(data)[:500]}
        if fix:
            f.extra["fix"] = fix
        return f

    def analyze(self) -> list[Finding]:
        out: list[Finding] = []
        for check in (self._winlogon, self._ifeo, self._appinit, self._shell_hijack, self._user_shell_folders,
                      self._policies, self._proxy, self._browser_policies, self._defender_exclusions):
            try:
                out.extend(check())
            except Exception as exc:  # uma verificação falha não derruba as demais
                log.warning("Verificação de registro %s falhou: %s", check.__name__, exc)
        return [f.finalize() for f in out]

    # --- Winlogon / persistência -------------------------------------------------------
    def _winlogon(self):
        a, out = self.a, []
        cat = "Persistência no Winlogon"
        shell = a.get(HKLM, WINLOGON, "Shell")
        if shell is not None and str(shell).strip().lower() != "explorer.exe":
            out.append(self._finding(HKLM, WINLOGON, "Shell", "wl_shell", f"Shell do Winlogon alterado: {shell}", 60, cat,
                                     shell, _fix_spec(HKLM, WINLOGON, "Shell", ("set", "explorer.exe", "REG_SZ"))))
        ui = a.get(HKLM, WINLOGON, "Userinit")
        if ui is not None:
            expected = norm(os.environ.get("SystemRoot", r"C:\Windows")) + r"\system32\userinit.exe"
            extra = [p for p in (x.strip() for x in str(ui).split(",")) if p and norm(p) != expected]
            if extra:
                std = os.environ.get("SystemRoot", r"C:\Windows") + r"\system32\userinit.exe,"
                out.append(self._finding(HKLM, WINLOGON, "Userinit", "wl_userinit",
                                         f"Userinit executa programas adicionais: {', '.join(extra)}", 60, cat, ui,
                                         _fix_spec(HKLM, WINLOGON, "Userinit", ("set", std, "REG_SZ"))))
        if a.get(HKLM, WINLOGON, "Taskman") not in (None, ""):
            out.append(self._finding(HKLM, WINLOGON, "Taskman", "wl_taskman",
                                     "Winlogon\\Taskman definido (substitui o Gerenciador de Tarefas)", 40, cat,
                                     a.get(HKLM, WINLOGON, "Taskman")))
        user_shell = a.get(HKCU, WINLOGON.replace("SOFTWARE", "Software", 1), "Shell")
        if user_shell not in (None, ""):
            out.append(self._finding(HKCU, WINLOGON.replace("SOFTWARE", "Software", 1), "Shell", "wl_user_shell",
                                     "Shell do Winlogon sobrescrito para o usuário atual", 50, cat, user_shell))
        return out

    def _ifeo(self):
        out = []
        for sub in self.a.subkeys(HKLM, IFEO):
            dbg = self.a.get(HKLM, rf"{IFEO}\{sub}", "Debugger")
            if not dbg:
                continue
            key = rf"{IFEO}\{sub}"
            fix = _fix_spec(HKLM, key, "Debugger", "delete")
            if sub.lower() in ACCESSIBILITY:
                out.append(self._finding(HKLM, key, "Debugger", "ifeo_access",
                                         f"Backdoor clássico: {sub} redirecionado para {dbg}", 60,
                                         "Persistência/backdoor", dbg, fix))
            elif "vsjitdebugger" in str(dbg).lower():
                out.append(self._finding(HKLM, key, "Debugger", "ifeo_vs",
                                         f"Depurador JIT registrado para {sub} (comum em máquinas de desenvolvimento)",
                                         5, "Persistência suspeita", dbg, fix))
            else:
                out.append(self._finding(HKLM, key, "Debugger", "ifeo_dbg",
                                         f"Image File Execution Options desvia {sub} para {dbg}", 40,
                                         "Persistência suspeita", dbg, fix))
        return out

    def _appinit(self):
        out = []
        for root in (WINDOWS_NT, WINDOWS_NT.replace(r"SOFTWARE\Microsoft", r"SOFTWARE\Wow6432Node\Microsoft")):
            val = self.a.get(HKLM, root, "AppInit_DLLs")
            if val and str(val).strip():
                out.append(self._finding(HKLM, root, "AppInit_DLLs", "appinit",
                                         f"AppInit_DLLs injeta DLLs em processos: {val}", 40, "Injeção de DLL", val,
                                         _fix_spec(HKLM, root, "AppInit_DLLs", ("set", "", "REG_SZ"))
                                         if root == WINDOWS_NT else None))
        return out

    def _shell_hijack(self):
        out = []
        for c in CLASS_COMMANDS:
            key = rf"SOFTWARE\Classes\{c}\shell\open\command"
            val = self.a.get(HKLM, key, "")
            if val is not None and str(val).strip().lower() != '"%1" %*':
                out.append(self._finding(HKLM, key, "", "assoc_hijack", f"Associação de {c} sequestrada: {val}", 60,
                                         "Sequestro de associação", val,
                                         _fix_spec(HKLM, key, "", ("set", '"%1" %*', "REG_SZ"))))
        ext = self.a.get(HKLM, r"SOFTWARE\Classes\.exe", "")
        if ext is not None and str(ext).strip().lower() != "exefile":
            out.append(self._finding(HKLM, r"SOFTWARE\Classes\.exe", "", "assoc_exe",
                                     f"Extensão .exe associada a '{ext}' em vez de exefile", 60,
                                     "Sequestro de associação", ext,
                                     _fix_spec(HKLM, r"SOFTWARE\Classes\.exe", "", ("set", "exefile", "REG_SZ"))))
        for h in UAC_BYPASS_HANDLERS:  # técnica de bypass de UAC por HKCU\Software\Classes
            key = rf"Software\Classes\{h}\Shell\Open\command"
            vals = self.a.values(HKCU, key)
            if vals:
                data = vals.get("", next(iter(vals.values())))[0]
                f = self._finding(HKCU, key, "", "uac_bypass", f"Handler de '{h}' definido no perfil do usuário "
                                  "(técnica de bypass de UAC/persistência)", 40, "Sequestro de associação", data)
                if in_temp_dir(expand_env(str(data)).strip('"')):
                    f.add("uac_bypass_temp", "O handler aponta para diretório temporário", 20)
                out.append(f)
        return out

    def _user_shell_folders(self):
        val, appdata = self.a.get(HKCU, USER_SHELL, "Startup"), os.environ.get("APPDATA")
        if not val or not appdata:
            return []
        expected = norm(os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
        if norm(expand_env(str(val))) != expected:
            return [self._finding(HKCU, USER_SHELL, "Startup", "startup_folder_moved",
                                  f"Pasta Startup redirecionada para {val}", 35, "Persistência suspeita", val,
                                  _fix_spec(HKCU, USER_SHELL, "Startup", (
                                      "set", r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
                                      "REG_EXPAND_SZ")))]
        return []

    # --- políticas, proxy, navegadores ---------------------------------------------------
    def _policies(self):
        out = []
        for hive, key, value, bad, code, desc, weight, how in POLICY_CHECKS:
            val = self.a.get(hive, key, value)
            if val in bad:
                out.append(self._finding(hive, key, value, code, desc, weight, "Alteração de política de segurança",
                                         val, _fix_spec(hive, key, value, how)))
        return out

    def _proxy(self):
        out, a = [], self.a
        server, enabled = a.get(HKCU, INET, "ProxyServer"), a.get(HKCU, INET, "ProxyEnable")
        if enabled == 1 and server:
            loop = bool(re.search(r"(127\.\d+\.\d+\.\d+|localhost)", str(server), re.I))
            out.append(self._finding(HKCU, INET, "ProxyEnable", "proxy_on",
                                     f"Proxy do sistema ativo: {server}" + (" (loopback: típico de interceptação)" if loop else
                                                                          " (comum em redes corporativas)"),
                                     20 if loop else 12, "Proxy/redirecionamento", server,
                                     _fix_spec(HKCU, INET, "ProxyEnable", ("set", 0, "REG_DWORD"))))
        pac = a.get(HKCU, INET, "AutoConfigURL")
        if pac:
            out.append(self._finding(HKCU, INET, "AutoConfigURL", "proxy_pac", f"Script de configuração de proxy (PAC): {pac}",
                                     15, "Proxy/redirecionamento", pac, _fix_spec(HKCU, INET, "AutoConfigURL", "delete")))
        return out

    def _browser_policies(self):
        out = []
        for hive in (HKLM, HKCU):
            for browser, key in BROWSER_POLICIES:
                names = {n.lower(): n for n in list(self.a.values(hive, key)) + self.a.subkeys(hive, key)}
                for low, original in names.items():
                    if low in BROWSER_SENSITIVE:
                        out.append(self._finding(hive, key, original, "browser_policy",
                                                 f"Política do {browser} altera '{original}' (legítimo em computadores "
                                                 "gerenciados; suspeito em PC pessoal)", 20, "Política de navegador",
                                                 self.a.get(hive, key, original)))
        return out

    def _defender_exclusions(self):
        if self.defender is None:
            return []
        ex, out = self.defender.exclusions(), []
        for p in ex.get("Paths", []):
            risky = in_user_writable_dir(p) or len(norm(p).strip("\\")) <= 3
            out.append(self._finding("Defender", "Exclusao", p, "def_excl_path",
                                     f"Exclusão de verificação no Defender: {p}" +
                                     (" (diretório gravável pelo usuário ou unidade inteira)" if risky else ""),
                                     30 if risky else 10, "Exclusão do Defender", p))
        for e in ex.get("Extensions", []):
            risky = e.lower() in RISKY_EXCLUDED_EXT
            out.append(self._finding("Defender", "ExclusaoExtensao", e, "def_excl_ext",
                                     f"Extensão excluída da verificação: {e}", 30 if risky else 5, "Exclusão do Defender", e))
        for pr in ex.get("Processes", []):
            out.append(self._finding("Defender", "ExclusaoProcesso", pr, "def_excl_proc",
                                     f"Processo excluído da verificação: {pr}", 10, "Exclusão do Defender", pr))
        return out


class RegistryFixer:
    """Aplica correções pontuais. Exige confirmação, valida contra a lista de permissões e
    exporta um backup .reg da chave antes de escrever."""

    def __init__(self, access=None, db=None, backup=None):
        self.a = access if access is not None else RegistryAccess()
        self.db, self.backup = db, backup or backup_key

    def apply(self, finding: Finding, confirmed: bool) -> Path | None:
        if not confirmed:
            raise RegistryError("A correção exige confirmação explícita do usuário.")
        fix = finding.extra.get("fix")
        if not fix:
            raise RegistryError("Não há correção automática segura para este item; revise manualmente.")
        if not _is_allowed_fix(fix):
            raise RegistryError("Correção fora da lista de permissões; operação recusada.")
        hive, key, value = fix["hive"], fix["key"], fix["value"]
        backup_path = self.backup(hive, key) if self.a.key_exists(hive, key) else None
        try:
            if fix["action"] == "delete_value":
                self.a.delete_value(hive, key, value)
            else:
                self.a.set_value(hive, key, value, fix["data"], fix.get("type", "REG_SZ"))
        except RegistryError as exc:
            if self.db:
                self.db.log_action("registry_fix", finding.path, str(exc), False)
            raise
        if self.db:
            self.db.log_action("registry_fix", finding.path,
                               json.dumps({"fix": fix, "backup": str(backup_path) if backup_path else None}), True)
        log.info("Correção de registro aplicada: %s (backup=%s)", finding.path, backup_path)
        return backup_path
