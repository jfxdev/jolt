import { useEffect, useState } from "react";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Toggle } from "@/components/ui/toggle";
import {
  FILE_TYPE_CLASSES,
  cleanSelector,
  describeRule,
  emptySelector,
  parseTokens,
  validateTypedRule,
} from "@/lib/policy-rules";
import type { PolicyRule } from "@/lib/types";

interface Props {
  rule: PolicyRule;
  index: number;
  // The Control Tower accepts typed rules only when it was started with them.
  enabled: boolean;
  onChange: (rule: PolicyRule) => void;
}

// Lists are typed as free text; the text is kept here so a trailing comma
// survives while the operator is still typing the next entry.
function useListText(values: string[] | undefined) {
  const joined = (values ?? []).join(", ");
  const [text, setText] = useState(joined);
  useEffect(() => {
    // A rule removed above shifts this one up: follow the rule, not the typing.
    setText((current) => (parseTokens(current).join(", ") === joined ? current : joined));
  }, [joined]);
  return [text, setText] as const;
}

export function TypedRuleFields({ rule, index, enabled, onChange }: Props) {
  const typed = Boolean(rule.file_types);
  const [extensions, setExtensions] = useListText(rule.file_types?.extensions);
  const [names, setNames] = useListText(rule.file_types?.names);
  const problem = typed ? validateTypedRule(rule) : "";
  const summary = typed && !problem ? describeRule(rule) : "";

  function setTyped(on: boolean) {
    if (!on) {
      const rest: PolicyRule = { path: rule.path, capabilities: rule.capabilities };
      // A path denial stands alone again.
      onChange({ ...rest, capabilities: rest.capabilities.includes("deny") ? ["deny"] : rest.capabilities });
      return;
    }
    onChange({ ...rule, file_types: emptySelector(), visibility: rule.visibility ?? "hidden" });
  }

  function setClass(id: string, on: boolean) {
    const current = rule.file_types?.classes ?? [];
    const classes = on ? [...current, id] : current.filter((value) => value !== id);
    onChange({ ...rule, file_types: { ...rule.file_types, classes } });
  }

  return (
    <div className="grid gap-2 rounded-md border border-dashed p-2" data-testid={`typed-rule-${index}`}>
      <div className="flex items-center justify-between gap-2">
        <Label className="text-xs">Tipo de arquivo</Label>
        <Toggle
          type="button"
          variant="outline"
          size="sm"
          pressed={typed}
          disabled={!enabled && !typed}
          onPressedChange={setTyped}
          aria-label="Restringir por tipo de arquivo"
        >
          Restringir por tipo
        </Toggle>
      </div>
      {!enabled && (
        <small className="text-muted-foreground">
          {typed
            ? "Políticas por tipo estão desativadas neste Control Tower: esta regra será recusada ao salvar."
            : "Políticas por tipo estão desativadas neste Control Tower."}
        </small>
      )}
      {typed && (
        <>
          <fieldset className="grid grid-cols-2 gap-1">
            <legend className="mb-1 text-xs text-muted-foreground">Classes</legend>
            {FILE_TYPE_CLASSES.map((entry) => (
              <label key={entry.id} className="flex items-center gap-1.5 text-sm">
                <Checkbox
                  checked={rule.file_types?.classes?.includes(entry.id) ?? false}
                  onCheckedChange={(value) => setClass(entry.id, value === true)}
                  aria-label={`Classe ${entry.label}`}
                />
                {entry.label}
              </label>
            ))}
          </fieldset>
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="grid gap-1">
              <Label className="text-xs" htmlFor={`rule-${index}-extensions`}>
                Extensões
              </Label>
              <Input
                id={`rule-${index}-extensions`}
                value={extensions}
                placeholder="pem, key, p12"
                onChange={(event) => {
                  setExtensions(event.target.value);
                  onChange({
                    ...rule,
                    file_types: cleanSelectorKeepingEmpty({ ...rule.file_types, extensions: parseTokens(event.target.value) }),
                  });
                }}
              />
            </div>
            <div className="grid gap-1">
              <Label className="text-xs" htmlFor={`rule-${index}-names`}>
                Nomes exatos
              </Label>
              <Input
                id={`rule-${index}-names`}
                value={names}
                placeholder=".env, id_rsa"
                onChange={(event) => {
                  setNames(event.target.value);
                  onChange({
                    ...rule,
                    file_types: cleanSelectorKeepingEmpty({ ...rule.file_types, names: parseTokens(event.target.value) }),
                  });
                }}
              />
            </div>
          </div>
          <div className="grid gap-1">
            <Label className="text-xs" htmlFor={`rule-${index}-visibility`}>
              Quando bloqueado
            </Label>
            <NativeSelect
              id={`rule-${index}-visibility`}
              className="w-full"
              value={rule.visibility ?? "hidden"}
              onChange={(event) =>
                onChange({ ...rule, visibility: event.target.value === "visible" ? "visible" : "hidden" })
              }
            >
              <option value="hidden">Ocultar o arquivo</option>
              <option value="visible">Mostrar bloqueado</option>
            </NativeSelect>
          </div>
          {problem ? (
            <small role="alert" className="text-destructive">
              {problem}
            </small>
          ) : (
            summary && (
              <small className="text-muted-foreground" data-testid={`typed-rule-summary-${index}`}>
                {summary}
              </small>
            )
          )}
        </>
      )}
    </div>
  );
}

// While typing, an empty list is still "a selector being filled in": keep the
// object so the typed toggle does not flip off. Saving cleans it.
function cleanSelectorKeepingEmpty(selector: NonNullable<PolicyRule["file_types"]>) {
  return cleanSelector(selector) ?? emptySelector();
}
