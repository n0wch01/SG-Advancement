import { responseText } from "../format";
import type { Enforcement } from "../types";

// A decision is not proof of enforcement. Only an explicit confirmation gets the green treatment.
export function ResponseBadge({ response }: { response?: Enforcement | null }) {
  const confirmation = response?.confirmation;
  const tone = confirmation === "failed" || confirmation === "contradicted"
    ? "bad"
    : confirmation === "confirmed"
      ? "good"
      : response?.stage === "held" || response?.stage === "approval_requested" || confirmation === "unconfirmed"
        ? "warn"
        : "neutral";
  return <span className={`response-badge response-${tone}`}>{responseText(response)}</span>;
}
