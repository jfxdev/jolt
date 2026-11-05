import { Checkbox } from "@/components/ui/checkbox";
import {
  APPROVAL_CAPABILITIES,
  canAskApproval,
  describeApproval,
  setApproval,
  validateApproval,
} from "@/lib/policy-rules";
import type { PolicyRule } from "@/lib/types";

interface Props {
  rule: PolicyRule;
  index: number;
  // The Control Tower accepts approval marks only when it runs with approvals.
  enabled: boolean;
  onChange: (rule: PolicyRule) => void;
}

// Lets a rule grant delete or update only once a person approves each request.
export function ApprovalRuleFields({ rule, index, enabled, onChange }: Props) {
  const marks = rule.needs_approval ?? [];
  const offered = APPROVAL_CAPABILITIES.filter((entry) => canAskApproval(rule, entry.id) || marks.includes(entry.id));
  if (!offered.length) return null;
  const problem = validateApproval(rule);
  return (
    <fieldset className="grid gap-2 rounded-md border border-dashed p-2" data-testid={`approval-rule-${index}`}>
      <legend className="px-1 text-xs">Aprovação humana</legend>
      {offered.map((entry) => (
        <label key={entry.id} className="flex items-center gap-1.5 text-sm">
          <Checkbox
            checked={marks.includes(entry.id)}
            disabled={!enabled && !marks.includes(entry.id)}
            onCheckedChange={(value) => onChange(setApproval(rule, entry.id, value === true))}
            aria-label={`Exigir aprovação para ${entry.label.toLowerCase()}`}
          />
          Exigir aprovação para {entry.label.toLowerCase()}
        </label>
      ))}
      {!enabled && (
        <small className="text-muted-foreground">
          {marks.length
            ? "As aprovações estão desativadas neste Control Tower: com a marca, esta concessão é recusada."
            : "As aprovações estão desativadas neste Control Tower."}
        </small>
      )}
      {problem ? (
        <small role="alert" className="text-destructive">
          {problem}
        </small>
      ) : (
        marks.length > 0 && (
          <small className="text-muted-foreground" data-testid={`approval-summary-${index}`}>
            {describeApproval(rule)}
          </small>
        )
      )}
    </fieldset>
  );
}
