import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useRef,
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

export type WorkspaceSection = "mounts" | "jobs" | "trust" | "mtls";

interface WorkspaceContextValue {
 sectionErrors: Partial<Record<WorkspaceSection, string>>;
 retrySection: (section: WorkspaceSection) => Promise<void>;
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

  const currentNodeRef = useRef(nodeId); currentNodeRef.current = nodeId;
  const requests = useRef({ nodeId, sequences: { mounts: 0, jobs: 0, trust: 0, mtls: 0 } });
  if (requests.current.nodeId !== nodeId) {
    requests.current = { nodeId, sequences: { mounts: 0, jobs: 0, trust: 0, mtls: 0 } };
  }
  const [sectionErrors, setSectionErrors] = useState<Partial<Record<WorkspaceSection, string>>>({});
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
    setSectionErrors({});
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
        const results =
          await Promise.allSettled([
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
        const [mountResult, jobResult, trustResult, mtlsResult] = results;
        const loadedJobs = jobResult.status === "fulfilled" ? (jobResult.value as { items: Job[] }).items || [] : [];
        if (mountResult.status === "fulfilled") setMounts((mountResult.value as { items: Mount[] }).items || []);
        if (jobResult.status === "fulfilled") setJobs(loadedJobs);
        if (trustResult.status === "fulfilled") setTrust(trustResult.value as TrustView | null);
        if (mtlsResult.status === "fulfilled") setMtlsState(mtlsResult.value as MTLSState | null);
        const sections: WorkspaceSection[] = ["mounts", "jobs", "trust", "mtls"];
        const errors: Partial<Record<WorkspaceSection, string>> = {};
        results.forEach((result, index) => { if (result.status === "rejected") errors[sections[index]] = "Não foi possível atualizar esta seção."; });
        setSectionErrors(errors);
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

  const updateJobs = useCallback((updater: (previous: Job[]) => Job[]) => {
    if (currentNodeRef.current === nodeId) setJobs(updater);
  }, [nodeId]);
  useJobEvents(nodeId, canStreamJobs, updateJobs);

  const retrySection = useCallback(async (section: WorkspaceSection) => {
    if (!nodeId || currentNodeRef.current !== nodeId) return;
    const paths = { mounts: "mounts", jobs: "jobs", trust: "peers", mtls: "keys/mtls" };
    if (!hasPermissionNow(`nodes/${nodeId}/${paths[section]}`, section === "mtls" ? "read" : "list")) return;
    const request = requests.current;
    const ticket = ++request.sequences[section];
    const latest = () => requests.current === request && request.sequences[section] === ticket;
    try {
      if (section === "mounts") { const result = await api.mounts(nodeId); if (latest()) setMounts(result.items || []); }
      if (section === "jobs") { const result = await api.jobs(nodeId); if (latest()) setJobs(result.items || []); }
      if (section === "trust") { const result = await api.nodeTrust(nodeId); if (latest()) setTrust(result); }
      if (section === "mtls") { const result = await api.mtlsState(nodeId); if (latest()) setMtlsState(result); }
      if (latest()) setSectionErrors(previous => { const next = { ...previous }; delete next[section]; return next; });
    } catch (error) {
      if (latest()) { setSectionErrors(previous => ({ ...previous, [section]: "Não foi possível atualizar esta seção." })); handleError(error); }
    }
  }, [nodeId, hasPermissionNow, handleError]);
  const refreshJobs = useCallback(() => retrySection("jobs"), [retrySection]);
  const refreshMounts = useCallback(() => retrySection("mounts"), [retrySection]);
  const refreshTrust = useCallback(() => retrySection("trust"), [retrySection]);
  const refreshMTLSState = useCallback(() => retrySection("mtls"), [retrySection]);

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
      setJobs: updateJobs,
      sectionErrors,
      retrySection,
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
    nodePath, updateJobs, sectionErrors, retrySection,
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
