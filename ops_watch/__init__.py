"""Независимая проверка снимков состояния без доступа к production."""

from .core import InputError, analyze, changes

__all__ = ["InputError", "analyze", "changes"]
