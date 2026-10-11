import { ChevronDown } from "lucide-react";
import type {
  GrantDirection,
  GrantPermissions,
  Mount,
  Peer,
} from "@/lib/types";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { GrantPermissionBadges, TransferDirectionSelector } from "@/components/transfers/TransferAccess";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export interface GrantFormValue {
  peer_node_id: string;
  mount_id: string;
  path: string;
  direction: GrantDirection;
  permissions: GrantPermissions;
  conflict_policies: string[];
  visible_to_peer: boolean;
  enabled: boolean;
}

export const CONFLICT_OPTIONS = [
  { value: "fail", label: "Falhar" },
  { value: "skip", label: "Pular" },
  { value: "overwrite", label: "Sobrescrever" },
  { value: "rename", label: "Renomear" },
  { value: "ask", label: "Perguntar" },
  { value: "checksum", label: "Checksum" },
];

export function defaultGrantForm(): GrantFormValue {
  return {
    peer_node_id: "",
    mount_id: "",
    path: "",
    direction: "receive",
    permissions: { read: true, write: true, delete: false, rename: true },
    conflict_policies: ["fail"],
    visible_to_peer: true,
    enabled: true,
  };
}

/**
 * Direction and permissions must stay coherent or the node rejects the grant
 * (`send` forbids write/rename, `receive` requires write).
 */
export function withGrantDirection(
  form: GrantFormValue,
  direction: GrantDirection,
): GrantFormValue {
  if (direction === "send") {
    return {
      ...form,
      direction,
      permissions: { read: true, write: false, delete: false, rename: false },
      conflict_policies: [],
    };
  }
  if (direction === "receive") {
    return {
      ...form,
      direction,
      permissions: { ...form.permissions, write: true, delete: false },
      conflict_policies: ["fail"],
    };
  }
  return {
    ...form,
    direction,
    permissions: { ...form.permissions, read: true, write: true },
    conflict_policies: ["fail"],
  };
}

interface Props {
  value: GrantFormValue;
  onChange: (value: GrantFormValue) => void;
  mounts: Mount[];
  /** Omitted when the peer is already fixed by the surrounding flow. */
  peers?: Peer[];
  idPrefix?: string;
}

export function GrantFormFields({
  value,
  onChange,
  mounts,
  peers,
  idPrefix = "grant",
}: Props) {
  function setPermission(key: keyof GrantPermissions, allowed: boolean) {
    onChange({
      ...value,
      permissions: { ...value.permissions, [key]: allowed },
    });
  }

  return (
    <>
      {peers && (
        <div className="grid gap-2">
          <Label htmlFor={`${idPrefix}-peer`}>Node conectado</Label>
          <Select
            value={value.peer_node_id}
            onValueChange={(peer_node_id) =>
              onChange({ ...value, peer_node_id })
            }
          >
            <SelectTrigger id={`${idPrefix}-peer`} className="w-full">
              <SelectValue placeholder="Selecione um node">{peers.find((peer) => peer.node_id === value.peer_node_id)?.name}</SelectValue>
            </SelectTrigger>
            <SelectContent>
              {peers.map((peer) => (
                <SelectItem key={peer.node_id} value={peer.node_id}>
                  {peer.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}
      <div className="grid gap-2">
        <Label id={`${idPrefix}-direction`}>Este node pode</Label>
        <TransferDirectionSelector
          aria-labelledby={`${idPrefix}-direction`}
          value={value.direction}
          onValueChange={(direction) => onChange(withGrantDirection(value, direction))}
        />
      </div>
      <div className="grid gap-2">
        <Label htmlFor={`${idPrefix}-mount`}>Mount</Label>
        <Select
          value={value.mount_id}
          onValueChange={(mount_id) => onChange({ ...value, mount_id })}
        >
          <SelectTrigger id={`${idPrefix}-mount`} className="w-full">
            <SelectValue placeholder="Selecione um mount">{mounts.find((mount) => mount.mount_id === value.mount_id)?.name}</SelectValue>
          </SelectTrigger>
          <SelectContent>
            {mounts.map((mount) => (
              <SelectItem key={mount.mount_id} value={mount.mount_id}>
                {mount.name} · {mount.mode === "read_write" ? "Leitura e escrita" : "Somente leitura"}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-2">
        <Label htmlFor={`${idPrefix}-path`}>Pasta autorizada</Label>
        <Input
          id={`${idPrefix}-path`}
          value={value.path}
          placeholder="Todas as pastas"
          onChange={(event) => onChange({ ...value, path: event.target.value })}
        />
      </div>
      <div className="flex flex-wrap gap-1" aria-label="Permissões selecionadas">
        <GrantPermissionBadges value={value.permissions} />
      </div>
      {value.direction !== "receive" && <div className="grid gap-1 rounded-lg border p-3">
        <PermissionSwitch id={`${idPrefix}-delete`} label="Permitir remoção dos arquivos de origem ao mover entre hosts" checked={value.permissions.delete} onCheckedChange={(checked) => setPermission("delete", checked)} />
        <p className="text-xs text-muted-foreground">Copiar mantém os arquivos na origem.</p>
      </div>}
      {value.permissions.delete && (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-muted-foreground">
          Ao mover, permite remover a origem autorizada após validar o SHA-256.
          Falhas e cancelamentos preservam os arquivos.
        </p>
      )}
      <Collapsible className="grid gap-3 border-t pt-2">
        <CollapsibleTrigger render={<Button type="button" variant="ghost" size="sm" className="group justify-between px-0" />}>
          Mais opções <ChevronDown className="group-data-[panel-open]:rotate-180" />
        </CollapsibleTrigger>
        <CollapsibleContent className="grid gap-4">
          {value.direction === "receive" && <PermissionSwitch id={`${idPrefix}-read`} label="Permitir leitura" checked={value.permissions.read} onCheckedChange={(checked) => setPermission("read", checked)} />}
          {value.direction !== "send" && <PermissionSwitch id={`${idPrefix}-rename`} label="Permitir renomear" checked={value.permissions.rename} onCheckedChange={(checked) => setPermission("rename", checked)} />}
          <PermissionSwitch id={`${idPrefix}-visible`} label="Visível para o outro node" checked={value.visible_to_peer} onCheckedChange={(visible_to_peer) => onChange({ ...value, visible_to_peer })} />
          {value.direction !== "send" && <div className="grid gap-2">
            <Label id={`${idPrefix}-conflict`}>Conflitos permitidos</Label>
            <ToggleGroup multiple aria-labelledby={`${idPrefix}-conflict`} value={value.conflict_policies} onValueChange={(policies) => { if (policies.length) onChange({ ...value, conflict_policies: [...policies] }); }} variant="outline" size="sm" className="w-full flex-wrap justify-start">
              {CONFLICT_OPTIONS.map((option) => <ToggleGroupItem key={option.value} value={option.value} className="rounded-full aria-pressed:bg-primary aria-pressed:text-primary-foreground">{option.label}</ToggleGroupItem>)}
            </ToggleGroup>
          </div>}
        </CollapsibleContent>
      </Collapsible>
    </>
  );
}

function PermissionSwitch({ id, label, checked, onCheckedChange }: { id: string; label: string; checked: boolean; onCheckedChange: (checked: boolean) => void }) {
  return <div className="flex items-center justify-between gap-3"><Label htmlFor={id} className="text-sm font-normal">{label}</Label><Switch id={id} checked={checked} onCheckedChange={onCheckedChange} /></div>;
}
