import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useParams } from "react-router-dom";
import { api } from "@/lib/api";
import type {
  Connection,
  Grant,
  Job,
  MTLSState,
  Mount,
  NodeInfo,
  PairingInvite,
  PairingRequest,
  Peer,
  TrustPeer,
  TrustView,
} from "@/lib/types";
import { useNodes } from "@/context/NodesContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useApiError } from "@/hooks/useApiError";
import { useJobEvents } from "@/hooks/useJobEvents";

interface WorkspaceContextValue {
  nodeId: string;
  node: NodeInfo | null;
  mounts: Mount[];
  jobs: Job[];
  /** Both sides of every trust relationship, resolved by the Control Tower. */
  trust: TrustView | null;
  trustPeers: TrustPeer[];
  peers: Peer[];
  grants: Grant[];
  connections: Connection[];
  pairingInvites: PairingInvite[];
  pairingRequests: PairingRequest[];
  mtlsState: MTLSState | null;
  loading: boolean;
  setJobs: (updater: (previous: Job[]) => Job[]) => void;
  refreshJobs: () => Promise<void>;
  refreshMounts: () => Promise<void>;
  refreshTrust: () => Promise<void>;
  refreshMTLSState: () => Promise<void>;
  /** `nodes/{id}[/suffix]` — permission path helper. */
  nodePath: (suffix?: string) => string;
}

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

const empty = () => Promise.resolve({ items: [] });

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const { nodeId } = useParams();
  const { nodes } = useNodes();
  const { loadPermissions, hasPermissionNow } = usePermissions();
  const handleError = useApiError();

  const [mounts, setMounts] = useState<Mount[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [trust, setTrust] = useState<TrustView | null>(null);
  const [mtlsState, setMtlsState] = useState<MTLSState | null>(null);
  const [loading, setLoading] = useState(false);
  const [canStreamJobs, setCanStreamJobs] = useState(false);

  const node = useMemo(
    () => nodes.find((n) => n.node_id === nodeId) || null,
    [nodes, nodeId],
  );

  const nodePath = useCallback(
    (suffix = "") =>
      nodeId ? `nodes/${nodeId}${suffix ? `/${suffix}` : ""}` : "",
    [nodeId],
  );

  useEffect(() => {
    if (!nodeId) return;
    let active = true;
    setMounts([]);
    setJobs([]);
    setTrust(null);
    setMtlsState(null);
    setCanStreamJobs(false);
    setLoading(true);

    (async () => {
      try {
        const base = `nodes/${nodeId}`;
        await loadPermissions([
          base,
          `${base}/mounts`,
          `${base}/jobs`,
          `${base}/peers`,
          `${base}/grants`,
          `${base}/transfers`,
          `${base}/admin/pairing`,
          `${base}/keys/mtls`,
          `${base}/keys/identity`,
          `control-tower/nodes/${nodeId}/token`,
        ]);
        // One trust request replaces the peers/grants/invites/requests
        // fan-out: it is the only view that knows what the other side sees.
        const [mountResult, jobResult, trustResult, mtlsResult] =
          await Promise.all([
            hasPermissionNow(`${base}/mounts`, "list")
              ? api.mounts(nodeId)
              : empty(),
            hasPermissionNow(`${base}/jobs`, "list")
              ? api.jobs(nodeId)
              : empty(),
            hasPermissionNow(`${base}/peers`, "list")
              ? api.nodeTrust(nodeId)
              : Promise.resolve(null),
            hasPermissionNow(`${base}/keys/mtls`, "read")
              ? api.mtlsState(nodeId)
              : Promise.resolve(null),
          ]);
        if (!active) return;
        const loadedJobs = (jobResult as { items: Job[] }).items || [];
        setMounts((mountResult as { items: Mount[] }).items || []);
        setJobs(loadedJobs);
        setTrust(trustResult as TrustView | null);
        setMtlsState(mtlsResult as MTLSState | null);

        const jobPaths = loadedJobs
          .slice(0, 100)
          .map((job) => `${base}/jobs/${job.job_id}`);
        if (jobPaths.length) await loadPermissions(jobPaths);
        if (active && hasPermissionNow(`${base}/jobs`, "list")) {
          setCanStreamJobs(true);
        }
      } catch (error) {
        if (active) handleError(error);
      } finally {
        if (active) setLoading(false);
      }
    })();

    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeId]);

  useJobEvents(nodeId, canStreamJobs, setJobs);

  const refreshJobs = useCallback(async () => {
    if (!nodeId) return;
    const result = await api.jobs(nodeId);
    setJobs(result.items || []);
  }, [nodeId]);

  const refreshMounts = useCallback(async () => {
    if (!nodeId) return;
    const result = await api.mounts(nodeId);
    setMounts(result.items || []);
  }, [nodeId]);

  const refreshTrust = useCallback(async () => {
    if (!nodeId || !hasPermissionNow(`nodes/${nodeId}/peers`, "list")) return;
    setTrust(await api.nodeTrust(nodeId));
  }, [nodeId, hasPermissionNow]);

  const refreshMTLSState = useCallback(async () => {
    if (!nodeId || !hasPermissionNow(nodePath("keys/mtls"), "read")) return;
    setMtlsState(await api.mtlsState(nodeId));
  }, [nodeId, hasPermissionNow, nodePath]);

  const value = useMemo(() => {
    const trustPeers = trust?.peers || [];
    return {
      nodeId: nodeId ?? "",
      node,
      mounts,
      jobs,
      trust,
      trustPeers,
      peers: trustPeers as Peer[],
      grants: trustPeers.flatMap((peer) => peer.grants || []),
      connections: trust?.connections || [],
      pairingInvites: trust?.invites || [],
      pairingRequests: trust?.requests || [],
      mtlsState,
      loading,
      setJobs,
      refreshJobs,
      refreshMounts,
      refreshTrust,
      refreshMTLSState,
      nodePath,
    };
  }, [
    nodeId,
    node,
    mounts,
    jobs,
    trust,
    mtlsState,
    loading,
    refreshJobs,
    refreshMounts,
    refreshTrust,
    refreshMTLSState,
    nodePath,
  ]);

  return (
    <WorkspaceContext.Provider value={value}>
      {children}
    </WorkspaceContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useWorkspace() {
  const context = useContext(WorkspaceContext);
  if (!context)
    throw new Error("useWorkspace must be used within WorkspaceProvider");
  return context;
}
