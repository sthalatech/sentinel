"""SecretProvider protocol: resolve a secret by name at runtime."""

from __future__ import annotations

from typing import Protocol


class SecretProvider(Protocol):
    """Resolves secret values so they never live in the repo."""

    def get(self, name: str) -> str:
        """Return the secret value for a variable name."""
        ...
