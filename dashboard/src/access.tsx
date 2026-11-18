import { createContext, useContext } from "react";
import type { Identity, Role } from "./types";

export const IdentityContext = createContext<Identity | null>(null);

export function usePermission(permission: string, legacyRole?: Role | null): boolean {
  const identity = useContext(IdentityContext);
  return identity ? identity.permissions.includes(permission) : legacyRole === "admin";
}

export function useGlobalPermission(permission: string): boolean {
  const identity = useContext(IdentityContext);
  return identity?.role === "admin" || !!identity?.bindings.some(
    (binding) => binding.project_id === null && binding.permissions.includes(permission),
  );
}

export const PAGE_PERMISSIONS: Record<string, string> = {
  overview: "activity.read", findings: "activity.read", finding: "activity.read", timeline: "activity.read",
  approvals: "activity.read", inventory: "devices.read", actions: "response.read", policy: "policy.read",
};
