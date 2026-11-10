import { useState, type FormEvent } from "react";
import { ArrowRight } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { ApiError } from "@/lib/types";
import { JoltLogo, JoltMark } from "@/components/brand/JoltLogo";

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await login(username, password);
      setPassword("");
    } catch (err) {
      setError((err as ApiError)?.message || "Falha ao entrar.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      <div className="relative isolate hidden flex-col justify-between overflow-hidden border-r bg-sidebar p-16 lg:flex">
        <div
          aria-hidden="true"
          className="absolute inset-0 -z-10 bg-brand-grid mask-[radial-gradient(ellipse_at_30%_40%,black,transparent_75%)]"
        />
        <JoltMark
          glow
          aria-hidden="true"
          className="absolute -right-24 -bottom-16 -z-10 w-[28rem] opacity-15"
        />
        <JoltLogo className="text-2xl" />
        <div className="grid gap-6">
          <p className="font-mono text-xs uppercase tracking-widest text-brand">
            Jolt network
          </p>
          <h1 className="text-5xl font-semibold leading-tight tracking-tight">
            Seus arquivos.
            <br />
            <span className="text-brand-gradient">Sob seu comando.</span>
          </h1>
          <p className="max-w-md text-muted-foreground">
            Uma torre de controle privada para navegar e operar seus nodes sem
            abrir o filesystem dos servidores.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
          <span className="size-1.5 rounded-full bg-brand" />
          <span className="size-1.5 rounded-full bg-brand/60" />
          <span className="size-1.5 rounded-full bg-brand/30" />
          Conexão direta entre nodes
        </div>
      </div>

      <div className="flex flex-col items-center justify-center gap-8 p-6">
        <JoltLogo className="text-2xl lg:hidden" />
        <Card className="w-full max-w-md">
          <CardHeader>
            <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Acesso protegido
            </p>
            <CardTitle className="text-2xl">Bem-vindo de volta</CardTitle>
            <CardDescription>Sessão protegida e auditável</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="grid gap-4" onSubmit={handleSubmit}>
              <div className="grid gap-2">
                <Label htmlFor="username">Usuário</Label>
                <Input
                  id="username"
                  value={username}
                  autoComplete="username"
                  required
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="password">Senha</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  autoComplete="current-password"
                  required
                  autoFocus
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
              {error ? (
                <p className="text-sm text-destructive">{error}</p>
              ) : null}
              <Button type="submit" disabled={submitting}>
                Entrar na torre <ArrowRight />
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
