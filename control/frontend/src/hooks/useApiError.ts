import { useCallback } from "react";
import { toast } from "sonner";
import { isUnauthorized, useAuth } from "@/context/AuthContext";
import type { ApiError } from "@/lib/types";

/**
 * Returns a handler that surfaces an API error as a toast and clears the
 * session when the backend answers 401 — the pattern repeated across every
 * loader in the original Vue app.
 */
export function useApiError() {
  const { clearUser } = useAuth();
  return useCallback(
    (error: unknown) => {
      if (isUnauthorized(error)) clearUser();
      const message =
        (error as ApiError)?.message ||
        "Não foi possível concluir a operação.";
      toast.error(message);
    },
    [clearUser],
  );
}
