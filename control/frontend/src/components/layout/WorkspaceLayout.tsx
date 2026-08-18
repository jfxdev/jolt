import { Outlet } from "react-router-dom";
import { WorkspaceProvider } from "@/context/WorkspaceContext";

export function WorkspaceLayout() {
  return (
    <WorkspaceProvider>
      <Outlet />
    </WorkspaceProvider>
  );
}
