"""Registro de telas da aplicação."""
from __future__ import annotations

from ..components.sidebar import NAV_ITEMS
from ..context import AppContext
from .base_view import BaseView
from .dashboard_view import DashboardView
from .defender_view import DefenderView
from .network_view import NetworkView
from .placeholder_view import PlaceholderView
from .processes_view import ProcessesView
from .quarantine_view import QuarantineView
from .scanner_view import ScannerView
from .startup_view import StartupView

SUBTITLES = {
    "dashboard": "Visão geral da proteção e da atividade recente",
    "scanner": "Análise de arquivos com progresso, cancelamento e resultados",
    "processes": "Processos ativos, indicadores e encerramento seguro",
    "network": "Conexões ativas e correlação com processos",
    "startup": "Mecanismos de inicialização do Windows (somente leitura por padrão)",
    "quarantine": "Itens isolados com restauração e exclusão confirmadas",
    "cleanup": "Limpeza conservadora de arquivos temporários",
    "defender": "Estado, definições e histórico do Microsoft Defender",
    "history": "Histórico unificado de varreduras, detecções e operações",
    "settings": "Preferências da interface, exclusões e desempenho",
}


def build_views(context: AppContext) -> dict[str, BaseView]:
    views: dict[str, BaseView] = {}
    for key, title, _icon in NAV_ITEMS:
        if key == "dashboard":
            views[key] = DashboardView(context)
        elif key == "scanner":
            views[key] = ScannerView(context)
        elif key == "processes":
            views[key] = ProcessesView(context)
        elif key == "network":
            views[key] = NetworkView(context)
        elif key == "startup":
            views[key] = StartupView(context)
        elif key == "quarantine":
            views[key] = QuarantineView(context)
        elif key == "defender":
            views[key] = DefenderView(context)
        else:
            views[key] = PlaceholderView(context, key, title, SUBTITLES.get(key, ""))
    return views


__all__ = ["build_views", "BaseView", "SUBTITLES"]
