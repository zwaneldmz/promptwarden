import { Policy } from "@wardkeep/policy-engine";

/**
 * Standalone default: the privacy-conscious individual's profile.
 * Everything an org needs beyond this (profiles, central logging, SSO)
 * lives in the console — this file is the free/paid boundary in code form.
 */
export const FALLBACK_POLICY: Policy = {
  version: 1,
  name: "standalone-default",
  hosts: [
    "chatgpt.com",
    "chat.openai.com",
    "claude.ai",
    "gemini.google.com",
    "copilot.microsoft.com",
    "chat.mistral.ai",
    "www.perplexity.ai",
  ],
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
