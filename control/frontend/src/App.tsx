import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import { PermissionsProvider } from "@/context/PermissionsContext";
import { NodesProvider } from "@/context/NodesContext";
import { ConfirmProvider } from "@/context/ConfirmProvider";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { AppShell } from "@/components/layout/AppShell";
import { WorkspaceLayout } from "@/components/layout/WorkspaceLayout";
import LoginPage from "@/pages/LoginPage";
import NetworkOverviewPage from "@/pages/NetworkOverviewPage";
import RelationshipsPage from "@/pages/RelationshipsPage";
import NodeWorkspacePage from "@/pages/NodeWorkspacePage";
import FileBrowserPage from "@/pages/FileBrowserPage";
import AccessPage from "@/pages/AccessPage";
import IdentityPage from "@/pages/IdentityPage";
import PublicSharePage from "@/pages/PublicSharePage";

function Splash() {
  return (
    <div className="grid min-h-screen place-content-center text-muted-foreground">
      Preparando a Control Tower…
    </div>
  );
}

function LoginRoute() {
  const { user, authenticating } = useAuth();
  if (authenticating) return <Splash />;
  if (user) return <Navigate to="/" replace />;
  return <LoginPage />;
}

function Gate() {
  const { authenticating } = useAuth();
  if (authenticating) return <Splash />;
  return (
    <Routes>
      <Route path="/login" element={<LoginRoute />} />
      {/* Share links are public: they must render without a session and must
          not be caught by the authenticated gate below. */}
      <Route path="/s/:token" element={<PublicSharePage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route index element={<NetworkOverviewPage />} />
          <Route path="relationships" element={<RelationshipsPage />} />
          <Route path="access" element={<AccessPage />} />
          <Route path="identity" element={<IdentityPage />} />
          <Route path="nodes/:nodeId" element={<WorkspaceLayout />}>
            <Route index element={<NodeWorkspacePage />} />
            <Route path="mounts/:mountId" element={<FileBrowserPage />} />
          </Route>
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <PermissionsProvider>
        <NodesProvider>
          <ConfirmProvider>
            <Gate />
          </ConfirmProvider>
        </NodesProvider>
      </PermissionsProvider>
    </AuthProvider>
  );
}
