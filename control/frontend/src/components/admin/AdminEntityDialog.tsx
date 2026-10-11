import type { ReactNode } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface AdminEntityDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  children: ReactNode;
}

export function AdminEntityDialog({
  open,
  onOpenChange,
  title,
  children,
}: AdminEntityDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        {children}
      </DialogContent>
    </Dialog>
  );
}

interface EntityDialogFormLayoutProps {
  summary: ReactNode;
  children: ReactNode;
}

export function EntityDialogFormLayout({
  summary,
  children,
}: EntityDialogFormLayoutProps) {
  return (
    <div className="grid gap-6 md:grid-cols-[13rem_minmax(0,1fr)]">
      <div className="grid content-start gap-3">{summary}</div>
      <div className="grid content-start gap-3">{children}</div>
    </div>
  );
}
