import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { expiryLabel, expiryTone, kindLabel, needsAttention, shortFingerprint, sortCertificates, stateLabel, type Tone } from "@/lib/certificates";
import type { AuthorizationKeys, CertificateInventory } from "@/lib/types";
import { formatDate } from "@/lib/format";
import { useApiError } from "@/hooks/useApiError";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";

const TONE_CLASS: Record<Tone, string> = {
  ok: "",
  neutral: "text-muted-foreground",
  warning: "text-amber-600 dark:text-amber-400",
  critical: "font-medium text-destructive",
};

// The Control Tower's own certificate authority: what exists, when it ends and
// the fingerprint a person compares before installing the root. Every renewal
// happens by itself; nothing here asks anyone to do anything.
export function CertificatesPanel({ active }: { active: boolean }) {
  const handleError = useApiError();
  const [enabled, setEnabled] = useState<boolean>();
  const [inventory, setInventory] = useState<CertificateInventory>();
  const [keys, setKeys] = useState<AuthorizationKeys>();
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async () => {
    try {
      const [next, nextKeys] = await Promise.all([api.certificateInventory(), api.authorizationKeys()]);
      setInventory(next);
      setKeys(nextKeys);
      setNow(Date.now());
    } catch (error) {
      handleError(error);
    }
  }, [handleError]);

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    void api
      .about()
      .then((about) => {
        if (!cancelled) setEnabled(about.features?.managed_tls === true);
      })
      .catch(() => {
        if (!cancelled) setEnabled(false);
      });
    return () => {
      cancelled = true;
    };
  }, [active]);

  useEffect(() => {
    if (!active || !enabled) return;
    void load();
  }, [active, enabled, load]);

  async function copyYaml() {
    if (!keys) return;
    try {
      await navigator.clipboard.writeText(keys.node_yaml);
      toast.success("Bloco copiado.");
    } catch {
      toast.error("Não foi possível copiar. Selecione o texto e copie manualmente.");
    }
  }

  if (enabled === false) {
    return (
      <p className="text-sm text-muted-foreground" role="status">
        Os certificados gerenciados não estão habilitados neste Control Tower (CONTROL_TOWER_TLS_MODE=managed).
      </p>
    );
  }

  const items = inventory ? sortCertificates(inventory.items) : [];
  return (
    <section className="grid gap-6" aria-label="Certificados">
      <p className="max-w-3xl text-sm text-muted-foreground">
        O Control Tower emite e renova sozinho os certificados e as chaves abaixo. Aqui você só confere as datas e o
        fingerprint da raiz antes de instalá-la num dispositivo.
      </p>
      {inventory && (
        <div className="grid gap-2 rounded-md border p-3" data-testid="root-fingerprint">
          <span className="text-xs uppercase tracking-widest text-muted-foreground">Raiz · SHA-256</span>
          <code className="break-all font-mono text-sm">{inventory.root_fingerprint_display}</code>
          <div>
            <a className={buttonVariants({ size: "sm", variant: "secondary" })} href="/.well-known/jolt/ca.pem" download="jolt-root-ca.pem">
              Baixar a raiz
            </a>
          </div>
        </div>
      )}
      {inventory && needsAttention(inventory.items, now) && (
        <p role="alert" className="text-sm text-amber-600 dark:text-amber-400" data-testid="certificate-attention">
          Algo em uso está perto de vencer. Confira as datas abaixo.
        </p>
      )}
      <ul className="grid gap-2">
        {items.map((item) => {
          const tone = expiryTone(item, now);
          return (
            <li key={`${item.kind}-${item.fingerprint}`} className="grid gap-1 rounded-md border p-3" data-testid="certificate">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <strong className="text-sm">{kindLabel(item.kind)}</strong>
                <Badge variant={item.state === "active" ? "secondary" : "outline"}>{stateLabel(item.state)}</Badge>
              </div>
              <p className="break-all text-sm">{item.subject}</p>
              <p className={`text-xs ${TONE_CLASS[tone]}`} data-tone={tone}>
                Vence em {formatDate(item.not_after)} · {expiryLabel(item, now)}
              </p>
              <p className="break-all font-mono text-xs text-muted-foreground">{shortFingerprint(item.fingerprint)}</p>
            </li>
          );
        })}
      </ul>
      {keys && (
        <div className="grid gap-2" data-testid="node-yaml">
          <h2 className="text-sm font-medium">Chaves públicas para o YAML de um node</h2>
          <p className="max-w-3xl text-xs text-muted-foreground">
            Só é preciso colar isto num node configurado à mão. Versão do pacote de confiança: {inventory?.bundle_version}.
          </p>
          <pre className="overflow-x-auto rounded-md border bg-muted p-3 text-xs">{keys.node_yaml}</pre>
          <div>
            <Button size="sm" variant="secondary" onClick={() => void copyYaml()}>
              Copiar bloco
            </Button>
          </div>
        </div>
      )}
    </section>
  );
}
