import { Outlet } from "react-router-dom";
import {
  WorkspaceProvider,
  useWorkspace,
  type WorkspaceSection,
} from "@/context/WorkspaceContext";
import { Button } from "@/components/ui/button";

const labels = {
  mounts: "Volumes",
  jobs: "Jobs",
  trust: "Confiança",
  mtls: "Certificados",
};
function WorkspaceContent() {
  const { sectionErrors, retrySection } = useWorkspace();
  return (
    <>
      {Object.entries(sectionErrors).map(([section, message]) => (
        <div
          key={section}
          role="status"
          className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-md border p-3 text-sm"
        >
          <span>
            {labels[section as WorkspaceSection]}: {message}
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void retrySection(section as WorkspaceSection)}
          >
            Tentar novamente
          </Button>
        </div>
      ))}
      <Outlet />
    </>
  );
}
export function WorkspaceLayout() {
  return (
    <WorkspaceProvider>
      <WorkspaceContent />
    </WorkspaceProvider>
  );
}
