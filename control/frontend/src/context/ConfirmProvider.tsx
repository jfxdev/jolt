import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { buttonVariants } from "@/components/ui/button";

interface ConfirmOptions {
  title: string;
  description?: string;
  confirmText?: string;
  cancelText?: string;
  destructive?: boolean;
}

interface PromptOptions {
  title: string;
  description?: string;
  label?: string;
  defaultValue?: string;
  placeholder?: string;
  confirmText?: string;
}

interface ConfirmContextValue {
  confirm: (options: ConfirmOptions) => Promise<boolean>;
  prompt: (options: PromptOptions) => Promise<string | null>;
}

const ConfirmContext = createContext<ConfirmContextValue | null>(null);

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [confirmState, setConfirmState] = useState<ConfirmOptions | null>(null);
  const [promptState, setPromptState] = useState<PromptOptions | null>(null);
  const [promptValue, setPromptValue] = useState("");
  const confirmResolver = useRef<((value: boolean) => void) | null>(null);
  const promptResolver = useRef<((value: string | null) => void) | null>(null);

  const confirm = useCallback((options: ConfirmOptions) => {
    setConfirmState(options);
    return new Promise<boolean>((resolve) => {
      confirmResolver.current = resolve;
    });
  }, []);

  const prompt = useCallback((options: PromptOptions) => {
    setPromptState(options);
    setPromptValue(options.defaultValue ?? "");
    return new Promise<string | null>((resolve) => {
      promptResolver.current = resolve;
    });
  }, []);

  const resolveConfirm = (result: boolean) => {
    confirmResolver.current?.(result);
    confirmResolver.current = null;
    setConfirmState(null);
  };

  const resolvePrompt = (result: string | null) => {
    promptResolver.current?.(result);
    promptResolver.current = null;
    setPromptState(null);
  };

  const value = useMemo(() => ({ confirm, prompt }), [confirm, prompt]);

  return (
    <ConfirmContext.Provider value={value}>
      {children}

      <AlertDialog
        open={confirmState !== null}
        onOpenChange={(open) => {
          if (!open) resolveConfirm(false);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{confirmState?.title}</AlertDialogTitle>
            {confirmState?.description ? (
              <AlertDialogDescription>
                {confirmState.description}
              </AlertDialogDescription>
            ) : null}
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => resolveConfirm(false)}>
              {confirmState?.cancelText ?? "Cancelar"}
            </AlertDialogCancel>
            <AlertDialogAction
              className={cn(
                confirmState?.destructive &&
                  buttonVariants({ variant: "destructive" }),
              )}
              onClick={() => resolveConfirm(true)}
            >
              {confirmState?.confirmText ?? "Confirmar"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <Dialog
        open={promptState !== null}
        onOpenChange={(open) => {
          if (!open) resolvePrompt(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{promptState?.title}</DialogTitle>
          </DialogHeader>
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              resolvePrompt(promptValue);
            }}
          >
            {promptState?.description ? (
              <p className="text-sm text-muted-foreground">
                {promptState.description}
              </p>
            ) : null}
            <div className="grid gap-2">
              {promptState?.label ? (
                <Label htmlFor="prompt-input">{promptState.label}</Label>
              ) : null}
              <Input
                id="prompt-input"
                value={promptValue}
                placeholder={promptState?.placeholder}
                autoFocus
                onChange={(e) => setPromptValue(e.target.value)}
              />
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => resolvePrompt(null)}
              >
                Cancelar
              </Button>
              <Button type="submit">
                {promptState?.confirmText ?? "Confirmar"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </ConfirmContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useConfirm() {
  const context = useContext(ConfirmContext);
  if (!context)
    throw new Error("useConfirm must be used within ConfirmProvider");
  return context.confirm;
}

// eslint-disable-next-line react-refresh/only-export-components
export function usePrompt() {
  const context = useContext(ConfirmContext);
  if (!context)
    throw new Error("usePrompt must be used within ConfirmProvider");
  return context.prompt;
}
