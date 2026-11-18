"""Permission vocabulary shared by the control plane and resource enforcement adapters."""

from __future__ import annotations

CONTROL_PERMISSIONS = frozenset(
    {
        "identity.manage",
        "devices.read",
        "devices.manage",
        "activity.read",
        "policy.read",
        "policy.write",
        "audit.read",
        "approvals.review",
        "response.read",
        "response.manage",
        "sessions.register",
    }
)
RESOURCE_PERMISSIONS = frozenset(
    {
        "source.read",
        "source.write",
        "tests.write",
        "ci.run",
        "pr.create",
        "secrets.read",
        "deploy.production",
    }
)
PERMISSIONS = CONTROL_PERMISSIONS | RESOURCE_PERMISSIONS
GLOBAL_ONLY = frozenset({"identity.manage", "devices.manage", "policy.read", "policy.write", "audit.read"})

ROLE_DEFAULTS: dict[str, frozenset[str]] = {
    "identity_admin": frozenset({"identity.manage", "devices.read", "devices.manage"}),
    "security_admin": frozenset(
        {
            "activity.read",
            "devices.read",
            "policy.read",
            "policy.write",
            "audit.read",
            "approvals.review",
        }
    ),
    "soc": frozenset({"activity.read", "devices.read", "response.read", "response.manage"}),
    "developer": frozenset(
        {
            "activity.read",
            "sessions.register",
            "source.read",
            "source.write",
            "tests.write",
            "ci.run",
            "pr.create",
        }
    ),
    "qa": frozenset({"activity.read", "sessions.register", "source.read", "tests.write", "ci.run"}),
}
