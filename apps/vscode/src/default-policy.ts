import { Policy } from "@wardkeep/policy-engine";

/**
 * Built-in fallback policy, used whenever `wardkeep.policyPath` is
 * unset, unreadable, or fails `parsePolicy` validation. Mirrors
 * apps/cli/src/policy.ts's BUILTIN_DEFAULT_POLICY (same profile as the
 * browser extension's FALLBACK_POLICY in apps/extension/src/default-policy.ts)
 * with the same adaptation the CLI makes: `hosts: []`, because there is no
 * notion of a browser tab's host inside an editor — every open document is
 * evaluated unconditionally.
 */
export const BUILTIN_DEFAULT_POLICY: Policy = {
  version: 1,
  name: "vscode-standalone-default",
  hosts: [],
  defaultAction: "allow",
  logging: "off",
  rules: [
    { detector: "credit_card", action: "warn" },
    { detector: "iban", action: "warn" },
    { detector: "api_key", action: "warn" },
    { detector: "at_svnr", action: "warn" },
    { detector: "email", action: "allow" },
    { detector: "phone", action: "allow" },
  ],
};
