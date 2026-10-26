"""Backend registry."""

from __future__ import annotations

from ..base import SandboxBackend, SandboxUnavailable

BACKENDS = ("docker", "kvm")


def list_backends() -> list:
    return list(BACKENDS)


def get_backend(name: str = "auto", config: dict | None = None) -> SandboxBackend:
    """Resolve a backend by name, or auto-select the strongest available one.

    Raises SandboxUnavailable (never falls back to host execution).
    """
    from .. import capabilities

    wanted = (name or "auto").strip().lower()
    if wanted == "auto":
        rep = capabilities.probe()
        chosen = rep.get("recommended")
        if not chosen:
            raise SandboxUnavailable(
                "no isolation backend available on this host; refusing to execute "
                "on the host. install docker or qemu+kvm.",
                install=capabilities.DOCKER_INSTALL + "   # or: " + capabilities.KVM_INSTALL,
                backend="auto",
            )
    elif wanted in BACKENDS:
        chosen = wanted
    else:
        raise SandboxUnavailable(
            f"unknown sandbox backend {name!r}; known: {', '.join(BACKENDS)}",
            backend=wanted,
        )

    if chosen == "docker":
        from .docker_backend import DockerBackend
        backend: SandboxBackend = DockerBackend(config=config)
    else:
        from .kvm_backend import KVMBackend
        backend = KVMBackend(config=config)

    info = backend.available()
    if not info.get("available"):
        raise SandboxUnavailable(
            f"sandbox backend {chosen!r} unavailable: {info.get('reason')}",
            install=info.get("install"),
            backend=chosen,
        )
    return backend
