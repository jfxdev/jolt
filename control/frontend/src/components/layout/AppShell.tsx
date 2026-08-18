import { Outlet } from "react-router-dom";
import { Header } from "./Header";
import { NodeSidebar } from "./NodeSidebar";

export function AppShell() {
  return (
    <div className="grid min-h-screen grid-cols-[270px_1fr] grid-rows-[64px_1fr]">
      <Header />
      <NodeSidebar />
      <main className="overflow-x-hidden p-6 lg:p-10">
        <Outlet />
      </main>
    </div>
  );
}
