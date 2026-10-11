import type { CSSProperties } from "react";
import { Outlet } from "react-router-dom";
import { AppSidebar } from "./AppSidebar";
import { SiteHeader } from "./SiteHeader";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";

export function AppShell() {
  return (
    <SidebarProvider
      style={{ "--sidebar-width": "17rem" } as CSSProperties}
    >
      <AppSidebar />
      <SidebarInset>
        <SiteHeader />
        <div className="flex flex-1 flex-col overflow-x-hidden p-4 md:p-6 lg:p-8">
          <Outlet />
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}
