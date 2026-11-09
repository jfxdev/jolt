import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { remainingLabel } from "@/lib/approvals";
import {
  NODE_YAML_SNIPPET,
  clampMinutes,
  enrollmentStateLabel,
  environmentLine,
  groupFingerprint,
  tokenStatus,
  tokenStatusLabel,
} from "@/lib/enrollments";
import { formatDate } from "@/lib/format";
import type { CreatedJoinToken, Enrollment, JoinToken } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm, usePrompt } from "@/context/ConfirmProvider";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const POLL_MS = 10_000;

// How a node joins the Control Tower's authority: an administrator makes a
// one-use token, hands it to the node, and the node does the rest. When a
// token asks for it, a person compares the node's fingerprint and approves.
export function EnrollmentsPanel() {
  const handleError = useApiError();
  const confirm = useConfirm();
  const prompt = usePrompt();
  const [tokens, setTokens] = useState<JoinToken[]>([]);
  const [pending, setPending] = useState<Enrollment[]>([]);
  const [created, setCreated] = useState<CreatedJoinToken>();
  const [name, setName] = useState("");
  const [approval, setApproval] = useState<"auto" | "manual">("auto");
  const [minutes, setMinutes] = useState(15);
  const [busy, setBusy] = useState("");
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async () => {
    try {
      const [nextTokens, nextPending] = await Promise.all([api.joinTokens(), api.enrollments("pending")]);
      setTokens(nextTokens.items ?? []);
      setPending(nextPending.items ?? []);
      setNow(Date.now());
    } catch (error) {
      handleError(error);
    }
  }, [handleError]);

  useEffect(() => {
    void load();
    const refresh = window.setInterval(() => void load(), POLL_MS);
    const tick = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      window.clearInterval(refresh);
      window.clearInterval(tick);
    };
  }, [load]);

  async function create() {
    setBusy("create");
    try {
      const token = await api.createJoinToken({ node_name: name.trim(), approval, valid_minutes: clampMinutes(minutes) });
      setCreated(token);
      setName("");
      await load();
    } catch (error) {
      handleError(error);
    } finally {
      setBusy("");
    }
  }

  async function copy(text: string, done: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(done);
    } catch {
      toast.error("Não foi possível copiar. Selecione o texto e copie manualmente.");
    }
  }

  async function approve(item: Enrollment) {
    const accepted = await confirm({
      title: `Aprovar o node ${item.node_name}?`,
      description: `Confira o fingerprint abaixo com o que o node mostrou no log de inicialização. Se não for o mesmo, rejeite. Fingerprint: ${groupFingerprint(item.node_fingerprint)}`,
      confirmText: "O fingerprint confere, aprovar",
      destructive: true,
    });
    if (!accepted) return;
    setBusy(item.enrollment_id);
    try {
      await api.approveEnrollment(item.enrollment_id);
      toast.success("Node aprovado.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy("");
      await load();
    }
  }

  async function reject(item: Enrollment) {
    const note = await prompt({
      title: `Rejeitar o node ${item.node_name}?`,
      description: "O node não entra e recebe o motivo.",
      confirmText: "Rejeitar",
      label: "Motivo (opcional)",
    });
    if (note === null) return;
    setBusy(item.enrollment_id);
    try {
      await api.rejectEnrollment(item.enrollment_id, note.trim());
      toast.success("Adesão rejeitada.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy("");
      await load();
    }
  }

  async function revoke(token: JoinToken) {
    setBusy(token.token_id);
    try {
      await api.revokeJoinToken(token.token_id);
      toast.success("Token revogado.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy("");
      await load();
    }
  }

  return (
    <section className="grid gap-6" aria-label="Adesão de nodes" data-testid="enrollments">
      <div className="grid gap-2">
        <h2 className="text-lg font-medium">Adesão de nodes</h2>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Crie um token de uso único, entregue-o ao node e pronto: o node confere a raiz, recebe o certificado e passa a se renovar
          sozinho. O token vale poucos minutos e só funciona uma vez.
        </p>
      </div>

      <form
        className="grid gap-3 rounded-md border p-3 md:grid-cols-[1fr_auto_auto_auto] md:items-end"
        onSubmit={(event) => {
          event.preventDefault();
          if (name.trim() && !busy) void create();
        }}
      >
        <div className="grid gap-1">
          <Label htmlFor="join-node-name">Nome do node</Label>
          <Input id="join-node-name" value={name} maxLength={64} onChange={(event) => setName(event.target.value)} placeholder="ex.: nas-sala" />
        </div>
        <div className="grid gap-1">
          <Label htmlFor="join-approval">Aprovação</Label>
          <select
            id="join-approval"
            className="h-9 rounded-md border bg-background px-2 text-sm"
            value={approval}
            onChange={(event) => setApproval(event.target.value === "manual" ? "manual" : "auto")}
          >
            <option value="auto">Automática</option>
            <option value="manual">Uma pessoa aprova</option>
          </select>
        </div>
        <div className="grid gap-1">
          <Label htmlFor="join-minutes">Validade (min)</Label>
          <Input id="join-minutes" type="number" min={1} max={1440} className="w-24" value={minutes} onChange={(event) => setMinutes(Number(event.target.value))} />
        </div>
        <Button type="submit" disabled={!name.trim() || busy === "create"}>
          Criar token
        </Button>
      </form>

      {created && (
        <div className="grid gap-3 rounded-md border border-warning/60 p-3" role="status" data-testid="created-token">
          <p className="text-sm font-medium">Token para {created.node_name}. Aparece só agora; copie antes de sair desta tela.</p>
          <pre className="overflow-x-auto break-all whitespace-pre-wrap rounded-md border bg-muted p-3 text-xs" data-testid="token-value">
            {environmentLine(created.token)}
          </pre>
          <p className="text-xs text-muted-foreground">
            Vale até {formatDate(created.expires_at)}. No node, ponha isto no ambiente (ou em <code>JOLT_JOIN_TOKEN_FILE</code>) e isto no{" "}
            <code>node.yaml</code>:
          </p>
          <pre className="overflow-x-auto rounded-md border bg-muted p-3 text-xs">{NODE_YAML_SNIPPET}</pre>
          <div className="flex gap-2">
            <Button size="sm" variant="secondary" onClick={() => void copy(environmentLine(created.token), "Token copiado.")}>
              Copiar token
            </Button>
            <Button size="sm" variant="outline" onClick={() => setCreated(undefined)}>
              Já copiei
            </Button>
          </div>
        </div>
      )}

      <div className="grid gap-2">
        <h3 className="text-sm font-medium">Aguardando aprovação</h3>
        {pending.length === 0 ? (
          <p className="text-sm text-muted-foreground" data-testid="no-pending-enrollments">
            Nenhum node aguardando.
          </p>
        ) : (
          <ul className="grid gap-2">
            {pending.map((item) => (
              <li key={item.enrollment_id} className="grid gap-2 rounded-md border p-3" data-testid="pending-enrollment">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <strong className="text-sm">{item.node_name}</strong>
                  <Badge variant="outline">
                    {enrollmentStateLabel(item.state)} · {remainingLabel(item.expires_at, now)}
                  </Badge>
                </div>
                <p className="break-all text-xs text-muted-foreground">
                  {item.api_endpoint} · de {item.remote_addr}
                </p>
                <p className="break-all font-mono text-sm" data-testid="enrollment-fingerprint">
                  {groupFingerprint(item.node_fingerprint)}
                </p>
                <div className="flex gap-2">
                  <Button size="sm" disabled={busy === item.enrollment_id} onClick={() => void approve(item)}>
                    Aprovar
                  </Button>
                  <Button size="sm" variant="secondary" disabled={busy === item.enrollment_id} onClick={() => void reject(item)}>
                    Rejeitar
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="grid gap-2">
        <h3 className="text-sm font-medium">Tokens</h3>
        {tokens.length === 0 ? (
          <p className="text-sm text-muted-foreground">Nenhum token criado.</p>
        ) : (
          <ul className="grid gap-2">
            {tokens.map((token) => {
              const status = tokenStatus(token, now);
              return (
                <li key={token.token_id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3" data-testid="join-token">
                  <div className="grid gap-0.5">
                    <strong className="text-sm">{token.node_name}</strong>
                    <span className="text-xs text-muted-foreground">
                      {token.approval === "manual" ? "aprovação por uma pessoa" : "aprovação automática"} · criado em {formatDate(token.created_at)}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={status === "waiting" ? "secondary" : "outline"}>{tokenStatusLabel(status)}</Badge>
                    {status !== "used" && (
                      <Button size="sm" variant="outline" disabled={busy === token.token_id} onClick={() => void revoke(token)}>
                        Revogar
                      </Button>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
}
