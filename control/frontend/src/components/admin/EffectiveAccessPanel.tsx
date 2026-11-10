import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import {
  EFFECTIVE_CAPABILITIES,
  describeReason,
  explainCell,
  outcomeLabel,
  outcomeSymbol,
  suggestPath,
} from "@/lib/effective-access";
import type {
  EffectiveAccessCheck,
  EffectiveAccessResponse,
  Mount,
  ServiceAccount,
  User,
} from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { useNodes } from "@/context/NodesContext";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface Subject {
  key: string;
  actorType: "user" | "service_account";
  id: string;
  label: string;
}

interface CheckRow extends EffectiveAccessCheck {
  rowId: number;
}

const CELL_STYLE = {
  allowed: "text-success",
  denied: "text-destructive",
  hidden: "text-warning",
  blocked: "text-warning",
  approval: "text-info",
} as const;

// Shows what an identity can do at concrete paths, as the Control Tower and the
// node would decide it. Typed rules need the entry type, so each row has one.
export function EffectiveAccessPanel({ active }: { active: boolean }) {
  const handleError = useApiError();
  const { nodes } = useNodes();
  const [subjects, setSubjects] = useState<Subject[]>([]);
  const [subjectKey, setSubjectKey] = useState("");
  const [rows, setRows] = useState<CheckRow[]>([]);
  const [nextRow, setNextRow] = useState(1);
  const [policyNames, setPolicyNames] = useState<Record<string, string>>({});
  const [firstMount, setFirstMount] = useState<{ node: string; mount: string }>();
  const [answer, setAnswer] = useState<EffectiveAccessResponse>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    void Promise.allSettled([api.users(), api.serviceAccounts(), api.policies("")]).then(
      ([users, accounts, policies]) => {
        if (cancelled) return;
        const found: Subject[] = [];
        if (users.status === "fulfilled") {
          for (const user of (users.value.items ?? []) as User[]) {
            found.push({ key: `user:${user.user_id}`, actorType: "user", id: user.user_id, label: `${user.username} · usuário (${user.role})` });
          }
        }
        if (accounts.status === "fulfilled") {
          for (const account of (accounts.value.items ?? []) as ServiceAccount[]) {
            found.push({
              key: `service_account:${account.service_account_id}`,
              actorType: "service_account",
              id: account.service_account_id,
              label: `${account.name} · ${account.kind === "agent" ? "agente" : "automação"}`,
            });
          }
        }
        setSubjects(found);
        if (policies.status === "fulfilled") {
          setPolicyNames(Object.fromEntries((policies.value.items ?? []).map((policy) => [policy.policy_id, policy.name])));
        }
        for (const failed of [users, accounts, policies]) {
          if (failed.status === "rejected") handleError(failed.reason);
        }
      },
    );
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  // One real mount makes the first row useful instead of a blank to fill in.
  useEffect(() => {
    const node = nodes[0];
    if (!active || !node || firstMount) return;
    let cancelled = false;
    void api
      .mounts(node.node_id)
      .then((result) => {
        if (cancelled) return;
        const mount = ((result.items ?? []) as Mount[])[0];
        setFirstMount({ node: node.node_id, mount: mount?.mount_id ?? "" });
      })
      .catch(() => {
        if (!cancelled) setFirstMount({ node: node.node_id, mount: "" });
      });
    return () => {
      cancelled = true;
    };
  }, [active, nodes, firstMount]);

  useEffect(() => {
    if (rows.length || !firstMount) return;
    setRows([{ rowId: 0, path: suggestPath(firstMount.node, firstMount.mount), entry_type: "directory" }]);
  }, [firstMount, rows.length]);

  function update(rowId: number, change: Partial<EffectiveAccessCheck>) {
    setRows((current) => current.map((row) => (row.rowId === rowId ? { ...row, ...change } : row)));
  }

  async function ask(event: React.FormEvent) {
    event.preventDefault();
    const subject = subjects.find((entry) => entry.key === subjectKey);
    if (!subject || !rows.length) return;
    setBusy(true);
    try {
      setAnswer(
        await api.effectiveAccess(
          subject.actorType,
          subject.id,
          rows.map(({ path, entry_type }) => ({ path: path.trim(), entry_type })),
        ),
      );
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="grid gap-4" aria-label="Acesso efetivo">
      <p className="max-w-3xl text-sm text-muted-foreground">
        Veja o que uma identidade pode fazer em um caminho, com as mesmas regras que o Control Tower
        e o node aplicam. Regras por tipo tratam arquivos e pastas de forma diferente: informe o
        tipo da entrada.
      </p>
      <form className="grid gap-3" onSubmit={ask}>
        <div className="grid gap-2 sm:max-w-md">
          <Label htmlFor="effective-subject">Identidade</Label>
          <NativeSelect
            id="effective-subject"
            className="w-full"
            value={subjectKey}
            onChange={(event) => setSubjectKey(event.target.value)}
            required
          >
            <option value="">Selecione…</option>
            {subjects.map((subject) => (
              <option key={subject.key} value={subject.key}>
                {subject.label}
              </option>
            ))}
          </NativeSelect>
        </div>
        <div className="grid gap-2">
          {rows.map((row, index) => (
            <div key={row.rowId} className="grid gap-2 sm:grid-cols-[1fr_160px_auto]">
              <Input
                aria-label={`Caminho ${index + 1}`}
                value={row.path}
                placeholder="nodes/<node>/files/mounts/<mount>/pasta/arquivo.pem"
                required
                onChange={(event) => update(row.rowId, { path: event.target.value })}
              />
              <NativeSelect
                aria-label={`Tipo da entrada ${index + 1}`}
                className="w-full"
                value={row.entry_type}
                onChange={(event) =>
                  update(row.rowId, { entry_type: event.target.value === "file" ? "file" : "directory" })
                }
              >
                <option value="directory">Pasta</option>
                <option value="file">Arquivo</option>
              </NativeSelect>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={rows.length === 1}
                onClick={() => setRows((current) => current.filter((entry) => entry.rowId !== row.rowId))}
              >
                Remover
              </Button>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={rows.length >= 50}
            onClick={() => {
              setRows((current) => [
                ...current,
                { rowId: nextRow, path: suggestPath(firstMount?.node, firstMount?.mount), entry_type: "file" },
              ]);
              setNextRow((value) => value + 1);
            }}
          >
            Adicionar caminho
          </Button>
          <Button type="submit" size="sm" disabled={busy || !subjectKey || !rows.length}>
            Consultar
          </Button>
        </div>
      </form>

      {answer && (
        <div className="grid gap-3" data-testid="effective-result">
          <p className="text-sm">
            Acesso efetivo de <strong>{answer.subject.name ?? answer.subject.id}</strong>
            {answer.subject.enabled ? "" : " (desativada)"}
          </p>
          {answer.notes.length > 0 && (
            <ul className="grid gap-1 rounded-md border border-warning/40 bg-warning/10 p-3 text-sm" role="status">
              {answer.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          )}
          <div className="overflow-x-auto rounded-md border">
            <Table aria-label="Acesso efetivo por caminho">
              <TableHeader>
                <TableRow>
                  <TableHead>Caminho</TableHead>
                  {EFFECTIVE_CAPABILITIES.map((capability) => (
                    <TableHead key={capability} className="text-center">
                      {capability}
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {answer.results.map((result, index) => (
                  <TableRow key={`${result.path}:${result.entry_type}:${index}`}>
                    <TableCell className="max-w-xs">
                      <code className="break-all text-xs">{result.path}</code>
                      <span className="ml-2 text-xs text-muted-foreground">
                        {result.entry_type === "file" ? "arquivo" : "pasta"}
                      </span>
                      {result.reason && (
                        <small className="block text-muted-foreground">{describeReason(result.reason)}</small>
                      )}
                    </TableCell>
                    {EFFECTIVE_CAPABILITIES.map((capability) => {
                      const cell = result.capabilities[capability];
                      if (!cell) return <TableCell key={capability} />;
                      return (
                        <TableCell
                          key={capability}
                          className={cn("text-center", CELL_STYLE[cell.outcome])}
                          title={explainCell(cell, policyNames)}
                          data-outcome={cell.outcome}
                        >
                          <span aria-hidden="true">{outcomeSymbol(cell.outcome)}</span>
                          <span className="sr-only">{outcomeLabel(cell.outcome)}</span>
                        </TableCell>
                      );
                    })}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <p className="text-xs text-muted-foreground">
            ✓ permitido · ✗ negado · ◌ oculto (some da listagem) · 🔒 bloqueado (aparece, mas não abre) · ✋ exige aprovação de uma pessoa.
            Passe o mouse sobre uma célula para ver as policies envolvidas.
          </p>
        </div>
      )}
    </section>
  );
}
