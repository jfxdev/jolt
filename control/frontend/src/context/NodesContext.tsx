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
import { api } from "@/lib/api";
import type { NodeInfo } from "@/lib/types";
import { useAuth } from "@/context/AuthContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useApiError } from "@/hooks/useApiError";

const CONTROL_PERMISSION_PATHS = [
  "control-tower/users",
  "control-tower/service-accounts",
  "control-tower/access-groups",
  "control-tower/policies",
  "control-tower/roles",
  "control-tower/nodes",
  "control-tower/connections",
  "control-tower/audit",
];

interface NodesContextValue {
  nodes: NodeInfo[];
  loading: boolean;
  loadNodes: () => Promise<NodeInfo[]>;
}

const NodesContext = createContext<NodesContextValue | null>(null);

export function NodesProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const { loadPermissions } = usePermissions();
  const handleError = useApiError();
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [loading, setLoading] = useState(false);

  const actorRef = useRef(user?.user_id); actorRef.current = user?.user_id;
  const inFlight = useRef<{ actor?: string; key: symbol; promise: Promise<NodeInfo[]> } | null>(null);
  const loadNodes = useCallback((): Promise<NodeInfo[]> => {
    const actor = actorRef.current;
    if (!actor) return Promise.resolve([]);
    if (inFlight.current?.actor === actor) return inFlight.current.promise;
    setLoading(true);
    const key = Symbol();
    const promise = (async () => {
      try {
        const result = await api.nodes();
        if (actorRef.current === actor) setNodes(result.items || []);
        return result.items || [];
      } catch (error) {
        if (actorRef.current === actor) handleError(error);
        throw error;
      } finally {
        if (actorRef.current === actor) setLoading(false);
        if (inFlight.current?.key === key) inFlight.current = null;
      }
    })();
    inFlight.current = { actor, key, promise };
    return promise;
  }, [handleError]);

  // Bootstrap once the user is authenticated: load control-tower permissions
  // and the node inventory (mirrors onMounted/login in the Vue app).
  useEffect(() => {
    if (!user) {
      setNodes([]);
      return;
    }
    (async () => {
      await loadPermissions(CONTROL_PERMISSION_PATHS);
      await loadNodes().catch(() => undefined);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  const value = useMemo(
    () => ({ nodes, loading, loadNodes }),
    [nodes, loading, loadNodes],
  );

  return (
    <NodesContext.Provider value={value}>{children}</NodesContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useNodes() {
  const context = useContext(NodesContext);
  if (!context) throw new Error("useNodes must be used within NodesProvider");
  return context;
}
