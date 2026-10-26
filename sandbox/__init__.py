"""bobbypin sandbox - safety layer.

Three features, one goal: analysis of untrusted targets must never be able to
damage the machine it runs on.

  * VM isolation  - execute a target inside a throwaway boundary (hardened
                    container or KVM/QEMU guest). A crash, a bugcheck or a
                    crash-loop is contained in the boundary.
  * Honeypots     - decoy credentials / license keys / wallets planted inside
                    that boundary, audited after the run, so any read or copy
                    is reported with evidence.
  * Telemetry     - opt-in (default OFF) run reporting to the operator's
                    dashboard. Aggregate run facts only.

Nothing in this package ever falls back to executing a target on the host.
If a boundary cannot be built, the call fails loudly.
"""

__version__ = "1.0.0"

from .base import RunRequest, RunRecord, SandboxBackend, SandboxError, SandboxUnavailable  # noqa: F401

__all__ = ["RunRequest", "RunRecord", "SandboxBackend", "SandboxError",
           "SandboxUnavailable", "__version__"]
