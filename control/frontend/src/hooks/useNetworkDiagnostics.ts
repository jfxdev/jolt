import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { runLimited } from "@/lib/concurrency";
import { useNodes } from "@/context/NodesContext";
import { usePermissions } from "@/context/PermissionsContext";
import type { JobSummary, Mount, MTLSState, TrustView } from "@/lib/types";

type Observation<T> = {
  value?: T;
  observedAt?: string;
  error?: string;
  restricted?: boolean;
};
export interface NodeDiagnostics {
  jobs: Observation<JobSummary>;
  mounts: Observation<Mount[]>;
  trust: Observation<TrustView>;
  mtls: Observation<MTLSState>;
}

export function useNetworkDiagnostics() {
  const { loadNodes } = useNodes();
  const { loadPermissions, hasPermissionNow } = usePermissions();
  const [diagnostics, setDiagnostics] = useState<
    Record<string, NodeDiagnostics>
  >({});
  const [error, setError] = useState<string>();

  useEffect(() => {
    let active = true;
    let running = false;
    const poll = async () => {
      if (document.hidden || running) return;
      running = true;
      try {
        const nodes = await loadNodes();
        if (!active) return;
        await loadPermissions(
          nodes.flatMap((node) =>
            ["jobs", "mounts", "peers", "keys/mtls"].map(
              (path) => `nodes/${node.node_id}/${path}`,
            ),
          ),
        );
        if (!active) return;
        setError(undefined);
        setDiagnostics((previous) =>
          Object.fromEntries(
            nodes.map((node) => [
              node.node_id,
              previous[node.node_id] || {
                jobs: {},
                mounts: {},
                trust: {},
                mtls: {},
              },
            ]),
          ),
        );
        const tasks: (() => Promise<void>)[] = [];
        for (const node of nodes) {
          const queries = [
            [
              "jobs",
              "jobs",
              "list",
              async (signal: AbortSignal) =>
                api.jobSummary(node.node_id, signal),
            ],
            [
              "mounts",
              "mounts",
              "list",
              async (signal: AbortSignal) =>
                (await api.mounts(node.node_id, signal)).items || [],
            ],
            [
              "trust",
              "peers",
              "list",
              async (signal: AbortSignal) =>
                api.nodeTrust(node.node_id, signal),
            ],
            [
              "mtls",
              "keys/mtls",
              "read",
              async (signal: AbortSignal) =>
                api.mtlsState(node.node_id, signal),
            ],
          ] as const;
          for (const [section, path, capability, request] of queries) {
            const allowed = hasPermissionNow(
              `nodes/${node.node_id}/${path}`,
              capability,
            );
            if (!allowed) {
              setDiagnostics((previous) => ({
                ...previous,
                [node.node_id]: {
                  ...previous[node.node_id],
                  [section]: { restricted: true },
                },
              }));
              continue;
            }
            tasks.push(async () => {
              if (!active) return;
              try {
                if (node.state === "offline" || node.state === "untrusted")
                  throw new Error("Node indisponível.");
                const value = await request(AbortSignal.timeout(5_000));
                if (active)
                  setDiagnostics((previous) => ({
                    ...previous,
                    [node.node_id]: {
                      ...previous[node.node_id],
                      [section]: {
                        value,
                        observedAt: new Date().toISOString(),
                      },
                    },
                  }));
              } catch {
                if (active)
                  setDiagnostics((previous) => ({
                    ...previous,
                    [node.node_id]: {
                      ...previous[node.node_id],
                      [section]: {
                        ...previous[node.node_id]?.[section],
                        restricted: false,
                        error: "Não foi possível atualizar.",
                      },
                    },
                  }));
              }
            });
          }
        }
        await runLimited(tasks);
      } catch {
        if (active)
          setError(
            "Não foi possível atualizar a visão da rede. Os últimos dados foram preservados.",
          );
      } finally {
        running = false;
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 15_000);
    const visible = () => {
      if (!document.hidden) void poll();
    };
    document.addEventListener("visibilitychange", visible);
    return () => {
      active = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [loadNodes, loadPermissions, hasPermissionNow]);
  return { diagnostics, error };
}
