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
      <div className="hidden flex-col justify-center gap-6 bg-muted/40 p-16 lg:flex">
        <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Jolt network
        </p>
        <h1 className="text-5xl font-semibold leading-tight tracking-tight">
          Seus arquivos.
          <br />
          Sob seu comando.
        </h1>
        <p className="max-w-md text-muted-foreground">
          Uma torre de controle privada para navegar e operar seus nodes sem
          abrir o filesystem dos servidores.
        </p>
        <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
          <span className="h-1.5 w-1.5 rounded-full bg-foreground" />
          <span className="h-1.5 w-1.5 rounded-full bg-foreground/60" />
          <span className="h-1.5 w-1.5 rounded-full bg-foreground/30" />
          Conexão direta entre nodes
        </div>
      </div>

      <div className="flex items-center justify-center p-6">
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
