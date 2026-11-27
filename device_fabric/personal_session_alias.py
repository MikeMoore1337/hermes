"""Expose the standard process termination name for managed sessions only."""
from __future__ import annotations

from typing import Any, Callable

ALIAS = 'kill_process'
TARGET = 'force_terminate'


def advertised_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add an alias without changing or widening the underlying PID contract."""
    if type(tools) is not list or any(type(tool) is not dict for tool in tools):
        raise ValueError('personal_session_alias_denied')
    matches = [tool for tool in tools if tool.get('name') == TARGET]
    if len(matches) != 1 or any(tool.get('name') == ALIAS for tool in tools):
        raise ValueError('personal_session_alias_denied')
    alias = dict(matches[0])
    alias['name'] = ALIAS
    alias['description'] = 'Terminate a terminal session started by this Commander device.'
    return [*tools, alias]


def dispatch(name: str, args: dict, forward: Callable[[str, dict], dict]) -> dict:
    """Map only an exact positive PID to the existing tracked-session handler."""
    if name == ALIAS:
        if (type(args) is not dict or set(args) != {'pid'} or type(args['pid']) is not int
                or not 1 <= args['pid'] <= 2_147_483_647):
            return {'content': [{'type': 'text', 'text': 'H454_PERSONAL_CALL_DENIED'}], 'isError': True}
        return forward(TARGET, args)
    return forward(name, args)
