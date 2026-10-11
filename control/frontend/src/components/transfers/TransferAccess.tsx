import { ArrowDownLeft, ArrowLeftRight, ArrowUpRight, Eye, PencilLine, TextCursorInput, Trash2 } from "lucide-react";
import { cn } from "cn";
import type { GrantDirection, GrantPermissions } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";

// One palette for direction buttons, badges and their icons in light/dark themes.
const tones = {
  violet: {
    icon: "text-violet-700 dark:text-violet-300",
    badge: "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300",
    selected: "aria-pressed:border-violet-500/40 aria-pressed:bg-violet-500/15 aria-pressed:text-violet-700 dark:aria-pressed:text-violet-300",
  },
  sky: {
    icon: "text-sky-700 dark:text-sky-300",
    badge: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300",
    selected: "aria-pressed:border-sky-500/40 aria-pressed:bg-sky-500/15 aria-pressed:text-sky-700 dark:aria-pressed:text-sky-300",
  },
  emerald: {
    icon: "text-emerald-700 dark:text-emerald-300",
    badge: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
    selected: "aria-pressed:border-emerald-500/40 aria-pressed:bg-emerald-500/15 aria-pressed:text-emerald-700 dark:aria-pressed:text-emerald-300",
  },
  amber: {
    icon: "text-amber-700 dark:text-amber-300",
    badge: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  },
  rose: {
    icon: "text-rose-700 dark:text-rose-300",
    badge: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  },
};

const directions = {
  send_receive: { label: "Ambos", description: "Enviar e receber", Icon: ArrowLeftRight, tone: tones.violet },
  send: { label: "Enviar", description: "Enviar", Icon: ArrowUpRight, tone: tones.sky },
  receive: { label: "Receber", description: "Receber", Icon: ArrowDownLeft, tone: tones.emerald },
};
const directionOrder: GrantDirection[] = ["send_receive", "send", "receive"];

export function transferDirectionLabel(direction: GrantDirection) {
  return directions[direction].description;
}

export function TransferDirectionIcon({ direction, className }: { direction: GrantDirection; className?: string }) {
  const { Icon, tone } = directions[direction];
  return <Icon aria-hidden="true" className={cn("size-4 shrink-0", tone.icon, className)} />;
}

export function TransferDirectionBadge({ direction, className }: { direction: GrantDirection; className?: string }) {
  const { label, description, tone } = directions[direction];
  return <Badge variant="outline" className={cn(tone.badge, className)} title={description} aria-label={description}><TransferDirectionIcon direction={direction} />{label}</Badge>;
}

interface DirectionSelectorProps {
  value: GrantDirection;
  onValueChange: (direction: GrantDirection) => void;
  disabled?: boolean;
  className?: string;
  "aria-label"?: string;
  "aria-labelledby"?: string;
}

export function TransferDirectionSelector({ value, onValueChange, disabled, className, ...ariaProps }: DirectionSelectorProps) {
  return <ToggleGroup
    {...ariaProps}
    value={[value]}
    multiple={false}
    disabled={disabled}
    onValueChange={(values) => {
      const direction = directionOrder.find((option) => option === values[0]);
      // A direction is required; clicking the current option keeps it selected.
      if (direction) onValueChange(direction);
    }}
    variant="outline"
    spacing={0}
    className={cn("w-full", className)}
  >
    {directionOrder.map((direction) => <ToggleGroupItem key={direction} value={direction} title={directions[direction].description} className={cn("flex-1", directions[direction].tone.selected)}><TransferDirectionIcon direction={direction} />{directions[direction].label}</ToggleGroupItem>)}
  </ToggleGroup>;
}

const permissions = {
  read: { label: "Leitura", Icon: Eye, tone: tones.sky },
  write: { label: "Escrita", Icon: PencilLine, tone: tones.emerald },
  rename: { label: "Renomear", Icon: TextCursorInput, tone: tones.amber },
  delete: { label: "Remover após mover", Icon: Trash2, tone: tones.rose },
};
const permissionOrder: (keyof GrantPermissions)[] = ["read", "write", "rename", "delete"];

export function GrantPermissionBadges({ value, className }: { value: GrantPermissions; className?: string }) {
  return permissionOrder.filter((key) => value[key]).map((key) => {
    const { label, Icon, tone } = permissions[key];
    return <Badge key={key} variant="outline" className={cn(tone.badge, className)}><Icon aria-hidden="true" className={tone.icon} />{label}</Badge>;
  });
}
