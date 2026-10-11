import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Download, FolderArchive, FolderOpen, Lock } from "lucide-react";
import { api } from "@/lib/api";
import type { ApiError, FileEntry, PublicShare } from "@/lib/types";
import { formatBytes, formatDate } from "@/lib/format";
import { FileEntryIcon } from "@/components/files/FileEntryIcon";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

/**
 * PublicSharePage renders a share link for a visitor with no account. It only
 * ever learns what the public metadata exposes: a display name and whether the
 * link is a file or a folder — never the node, mount or path behind it.
 */
export default function PublicSharePage() {
  const { token = "" } = useParams();
  const [share, setShare] = useState<PublicShare | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [message, setMessage] = useState("");
  const [password, setPassword] = useState("");
  const [unlocking, setUnlocking] = useState(false);
  const [path, setPath] = useState("");
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [listing, setListing] = useState(false);

  const load = useCallback(async () => {
    try {
      const response = await api.publicShare(token);
      setShare(response.share);
      setStatus("ready");
    } catch (error) {
      setStatus("error");
      setMessage(
        (error as ApiError)?.message ||
          "Este link não existe ou não está mais disponível.",
      );
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const listPath = useCallback(
    async (next: string) => {
      setListing(true);
      try {
        const response = await api.publicShareList(token, next);
        setEntries(response.items || []);
        setPath(next);
      } catch (error) {
        setMessage(
          (error as ApiError)?.message || "Não foi possível abrir esta pasta.",
        );
      } finally {
        setListing(false);
      }
    },
    [token],
  );

  // A directory share lists its root as soon as it is readable.
  useEffect(() => {
    if (share?.kind === "directory" && share.unlocked) void listPath("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [share?.kind, share?.unlocked]);

  async function unlock(event: React.FormEvent) {
    event.preventDefault();
    setUnlocking(true);
    setMessage("");
    try {
      await api.unlockPublicShare(token, password);
      setPassword("");
      await load();
    } catch (error) {
      setMessage((error as ApiError)?.message || "Senha incorreta.");
    } finally {
      setUnlocking(false);
    }
  }

  if (status === "loading") {
    return (
      <div className="grid min-h-screen place-content-center text-muted-foreground">
        Carregando link…
      </div>
    );
  }

  if (status === "error" || !share) {
    return (
      <div className="grid min-h-screen place-content-center px-4">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle>Link indisponível</CardTitle>
            <CardDescription>{message}</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  if (!share.unlocked) {
    return (
      <div className="grid min-h-screen place-content-center px-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lock className="size-4" /> Link protegido
            </CardTitle>
            <CardDescription>
              Informe a senha para acessar “{share.name}”.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="grid gap-3" onSubmit={unlock}>
              <div className="grid gap-2">
                <Label htmlFor="share-password">Senha</Label>
                <Input
                  id="share-password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </div>
              {message && <p className="text-sm text-destructive">{message}</p>}
              <Button type="submit" disabled={unlocking || password === ""}>
                {unlocking ? "Verificando…" : "Abrir"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    );
  }

  const crumbs = ["", ...path.split("/").filter(Boolean)];

  return (
    <div className="mx-auto grid max-w-4xl gap-4 px-4 py-8">
      <Card>
        <CardHeader>
          <CardTitle>{share.name}</CardTitle>
          <CardDescription>
            {share.kind === "directory" ? "Pasta compartilhada" : "Arquivo compartilhado"}
            {share.expires_at && ` · expira em ${formatDate(share.expires_at)}`}
            {share.remaining_downloads !== undefined &&
              ` · ${share.remaining_downloads} download${share.remaining_downloads === 1 ? "" : "s"} restante${share.remaining_downloads === 1 ? "" : "s"}`}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {share.kind === "file" && (
            <a className={buttonVariants()} href={api.publicShareContentUrl(token, "")}>
              <Download /> Baixar
            </a>
          )}
          {share.kind === "directory" && share.allow_archive && (
            <a
              className={buttonVariants({ variant: "secondary" })}
              href={api.publicShareArchiveUrl(token, path)}
            >
              <FolderArchive /> Baixar esta pasta (.zip)
            </a>
          )}
        </CardContent>
      </Card>

      {share.kind === "directory" && (
        <Card>
          <CardHeader>
            <CardDescription className="flex flex-wrap items-center gap-1">
              {crumbs.map((crumb, index) => {
                const target = crumbs.slice(1, index + 1).join("/");
                return (
                  <span key={target || "root"} className="flex items-center gap-1">
                    {index > 0 && <span>/</span>}
                    <button
                      className="transition-colors hover:text-foreground"
                      onClick={() => listPath(target)}
                    >
                      {index === 0 ? share.name : crumb}
                    </button>
                  </span>
                );
              })}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Nome</TableHead>
                  <TableHead>Tamanho</TableHead>
                  <TableHead>Modificado</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((entry) => (
                  <TableRow key={entry.path}>
                    <TableCell className="flex items-center gap-2">
                      <FileEntryIcon entry={entry} />
                      {entry.type === "directory" ? (
                        <button
                          className="truncate text-left hover:underline"
                          onClick={() => listPath(entry.path)}
                        >
                          {entry.name}
                        </button>
                      ) : (
                        <span className="truncate">{entry.name}</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {entry.type === "directory" ? "—" : formatBytes(entry.size)}
                    </TableCell>
                    <TableCell>{formatDate(entry.modified_at)}</TableCell>
                    <TableCell>
                      <a
                        className={buttonVariants({ variant: "ghost", size: "sm" })}
                        aria-label={
                          entry.type === "directory"
                            ? `Baixar ${entry.name} como .zip`
                            : `Baixar ${entry.name}`
                        }
                        href={
                          entry.type === "directory"
                            ? api.publicShareArchiveUrl(token, entry.path)
                            : api.publicShareContentUrl(token, entry.path)
                        }
                      >
                        {entry.type === "directory" ? <FolderOpen /> : <Download />}
                      </a>
                    </TableCell>
                  </TableRow>
                ))}
                {entries.length === 0 && !listing && (
                  <TableRow>
                    <TableCell colSpan={4} className="text-muted-foreground">
                      Esta pasta está vazia.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
            {message && <p className="mt-2 text-sm text-destructive">{message}</p>}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
