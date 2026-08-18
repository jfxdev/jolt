import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";

export function ProtectedRoute() {
  const { user, authenticating } = useAuth();
  if (authenticating) return null;
  if (!user) return <Navigate to="/login" replace />;
  return <Outlet />;
}
