import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
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
  "control-tower/policies",
  "control-tower/roles",
  "control-tower/nodes",
  "control-tower/connections",
  "control-tower/audit",
];

interface NodesContextValue {
  nodes: NodeInfo[];
  loading: boolean;
  loadNodes: () => Promise<void>;
}

const NodesContext = createContext<NodesContextValue | null>(null);

export function NodesProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const { loadPermissions } = usePermissions();
  const handleError = useApiError();
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [loading, setLoading] = useState(false);

  const loadNodes = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.nodes();
      setNodes(result.items || []);
    } catch (error) {
      handleError(error);
    } finally {
      setLoading(false);
    }
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
      await loadNodes();
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
