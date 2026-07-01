"""Environment-variable based SecretProvider implementation."""

from __future__ import annotations

import os
from collections.abc import Mapping

from sentinel.interfaces.secret_provider import SecretProvider


class EnvSecretProvider(SecretProvider):
    """Resolve secrets from an environment mapping."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ if environ is not None else os.environ

    def get(self, name: str) -> str:
        """Return the secret value for a variable name."""
        if name not in self._environ:
            raise KeyError(f"secret not found in environment: {name}")
        return self._environ[name]
