import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { api } from "@/lib/api";
import type { Capability } from "@/lib/types";

import { useAuth } from "@/context/AuthContext";

type PermissionMap = Record<string, Capability[]>;

function check(
  caps: Capability[] | undefined,
  capability: Capability,
): boolean {
  const list = caps || [];
  return (
    list.includes(capability) ||
    ((capability === "create" || capability === "update") &&
      list.includes("write"))
  );
}

interface PermissionsContextValue {
  /** Loads capabilities for the given paths and merges them into the map. */
  loadPermissions: (paths: string[]) => Promise<void>;
  /** Reactive check for render-time gating (re-renders when the map changes). */
  hasPermission: (path: string, capability: Capability) => boolean;
  /** Synchronous check against the latest loaded map (safe right after load). */
  hasPermissionNow: (path: string, capability: Capability) => boolean;
  reset: () => void;
}

const PermissionsContext = createContext<PermissionsContextValue | null>(null);

export function PermissionsProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const actor = useRef(user?.user_id); actor.current = user?.user_id;
  const [map, setMap] = useState<PermissionMap>({});
  // A ref mirror lets hasPermission read fresh values right after a load
  // without waiting for a re-render.
  const mapRef = useRef<PermissionMap>({});

  const loadPermissions = useCallback(async (paths: string[]) => {
    if (!paths.length) return;
    const requestedActor = actor.current;
    const result = await api.permissions(paths);
    if (requestedActor !== actor.current) return;
    mapRef.current = { ...mapRef.current, ...(result.paths || {}) };
    setMap(mapRef.current);
  }, []);

  const hasPermission = useCallback(
    (path: string, capability: Capability) => check(map[path], capability),
    [map],
  );

  const hasPermissionNow = useCallback(
    (path: string, capability: Capability) =>
      check(mapRef.current[path], capability),
    [],
  );

  const reset = useCallback(() => {
    mapRef.current = {};
    setMap({});
  }, []);

  useEffect(() => { reset(); }, [user, reset]);

  const value = useMemo(
    () => ({ loadPermissions, hasPermission, hasPermissionNow, reset }),
    [loadPermissions, hasPermission, hasPermissionNow, reset],
  );

  return (
    <PermissionsContext.Provider value={value}>
      {children}
    </PermissionsContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function usePermissions() {
  const context = useContext(PermissionsContext);
  if (!context)
    throw new Error("usePermissions must be used within PermissionsProvider");
  return context;
}
