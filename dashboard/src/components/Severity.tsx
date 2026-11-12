import { SEVERITY_LABEL } from "../format";
import type { Severity } from "../types";

// Status colors never carry meaning alone: every badge also shows the label.
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`sev sev-${severity}`}>
      <span className="sev-dot" aria-hidden="true" />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}
