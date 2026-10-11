export interface AdminDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Renders the manager as regular page content instead of an overlay. */
  inline?: boolean;
}
