# Guia de correção

Correções detalhadas, em nível de código, para os achados de `docs/ROADMAP.md`.
Cada seção traz: **objetivo**, **mudança proposta** (com trechos de código),
**arquivos afetados**, **risco/migração** e **como validar**.

Comentários de código em inglês para casar com o restante do repositório.

Índice:

- [P0.2 — Rate-limit e lockout no login](#p02)
- [P0.3 — Criptografia do banco do node](#p03)
- [C1 — KDF forte para a passphrase do SQLCipher](#c1)
- [C2 — Separação de subchaves com HKDF](#c2)
- [C3 — Fingerprint de 128 bits](#c3)
- [C4 — Fechar o furo de Origin no CSRF](#c4)
- [C5 — Pool de leitura no SQLite](#c5)
- [C6 — Reavaliar o componente final (TOCTOU)](#c6)
- [C7 — Trailer sentinela em erro de stat](#c7)
- [C8 — Segredos via `*_FILE`](#c8)
- [C9 — Hardening de container](#c9)
- [C10 — `SECURE_COOKIES` seguro por padrão](#c10)
- [C11 — Higiene de repositório](#c11)
- [C12 — Sweeper de sessões e convites](#c12)
- [F1 — Reancorar contenção na base real do grant](#f1)
- [F2 — Limite de tamanho de upload](#f2)

---

## <a id="p02"></a>P0.2 — Rate-limit e lockout no login

**Objetivo.** Impedir força bruta e password spraying em
`POST /api/v1/control-tower/auth/login`.

**Mudança.** Rastrear tentativas por `(username, ip)` com backoff e lockout.
Implementação durável no store (sobrevive a réplicas/restart). Tabela nova:

```sql
CREATE TABLE IF NOT EXISTS login_attempts (
    key           TEXT PRIMARY KEY, -- lower(username) + '|' + client_ip
    failures      INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT,
    updated_at    TEXT NOT NULL
);
```

Métodos no store (`control/internal/store/store.go`):

```go
// LoginGate retorna o instante até o qual a chave está bloqueada, ou zero.
func (s *Store) LoginLockedUntil(ctx context.Context, key string, now time.Time) (time.Time, error) {
	var lockedUntil sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT locked_until FROM login_attempts WHERE key=?`, key).Scan(&lockedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil || !lockedUntil.Valid {
		return time.Time{}, err
	}
	t, _ := time.Parse(time.RFC3339Nano, lockedUntil.String)
	if t.After(now) {
		return t, nil
	}
	return time.Time{}, nil
}

// RegisterLoginFailure incrementa e aplica lockout exponencial.
func (s *Store) RegisterLoginFailure(ctx context.Context, key string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var failures int
	_ = tx.QueryRowContext(ctx, `SELECT failures FROM login_attempts WHERE key=?`, key).Scan(&failures)
	failures++
	var lockedUntil string
	if failures >= 5 {
		// 5→30s, 6→60s, 7→120s … teto de 15min.
		backoff := time.Duration(math.Min(float64(30<<(failures-5)), 900)) * time.Second
		lockedUntil = now.Add(backoff).Format(time.RFC3339Nano)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO login_attempts(key,failures,locked_until,updated_at) VALUES(?,?,?,?)
ON CONFLICT(key) DO UPDATE SET failures=excluded.failures,
	locked_until=excluded.locked_until, updated_at=excluded.updated_at`,
		key, failures, nullIfEmpty(lockedUntil), now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ClearLoginFailures(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE key=?`, key)
	return err
}
```

Handler (`control/internal/httpapi/server.go`, `login`):

```go
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var request loginRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	now := time.Now().UTC()
	key := strings.ToLower(strings.TrimSpace(request.Username)) + "|" + clientIP(r)

	if until, err := s.store.LoginLockedUntil(r.Context(), key, now); err != nil {
		s.fail(w, r, err)
		return
	} else if !until.IsZero() {
		w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
		s.store.Audit(r.Context(), "", "login", "control-tower", "locked", r.Header.Get("X-Correlation-ID"))
		writeError(w, r, http.StatusTooManyRequests, "too_many_attempts",
			"Muitas tentativas. Tente novamente mais tarde.")
		return
	}

	user, err := s.store.UserByUsername(r.Context(), strings.TrimSpace(request.Username))
	if err != nil || !user.Enabled || !security.VerifyPassword(user.PasswordHash, request.Password) {
		_ = s.store.RegisterLoginFailure(r.Context(), key, now)
		s.store.Audit(r.Context(), "", "login", "control-tower", "denied", r.Header.Get("X-Correlation-ID"))
		writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "Usuário ou senha inválidos.")
		return
	}
	_ = s.store.ClearLoginFailures(r.Context(), key)
	// … restante inalterado (criar sessão, cookie, audit allowed).
}

// clientIP respeita X-Forwarded-For apenas atrás de proxy confiável.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
```

> `X-Forwarded-For` só deve ser considerado se o Control Tower estiver atrás de
> um proxy confiável; caso contrário o cliente falseia o IP e escapa do lockout.
> Ver `docs/REVERSE_PROXY.md`. Mantenha o lockout por `username` como âncora
> independente do IP.

**Risco/migração.** Baixo. Nova tabela via migração idempotente. Adicionar teto
por-usuário evita DoS de conta legítima por spray de IP (o lockout de IP não
deve bloquear o usuário real — priorize a chave por-usuário com contador
separado se necessário).

**Validar.** Teste que 5 falhas retornam `429` com `Retry-After`; sucesso limpa
o contador; lockout expira.

**Follow-up (MFA/TOTP).** Adicionar `totp_secret` (cifrado, ver [C2](#c2)) por
usuário e um segundo passo no login. Fora do escopo deste patch.

---

## <a id="p03"></a>P0.3 — Criptografia do banco do node

**Objetivo.** Cifrar o banco do node em repouso, com paridade ao Control Tower.

**Mudança.** Trocar o driver do node de `modernc.org/sqlite` (Go puro, sem
cipher) para o toolchain SQLCipher usado no control
(`github.com/mutecomm/go-sqlcipher/v4`), reusando `database.Open` já validado.

`node/backend/internal/infra/db/sqlite.go`:

```go
import (
	// remove: _ "modernc.org/sqlite"
	"github.com/jfxdev/jolt/... /database" // pacote compartilhado de abertura cifrada
)

func Open(path string, key []byte) (*Store, error) {
	db, err := database.Open(path, key, false) // aplica PRAGMA key + verifyCipher
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`); err != nil {
		return nil, err
	}
	// journal_mode=WAL é aplicado normalmente; ver nota SQLCipher+WAL abaixo.
	return &Store{db: db}, nil
}
```

Config (`node/backend/internal/infra/config/config.go`): adicionar
`JOLT_DB_ENCRYPTION_KEY` com a mesma validação de `ParseEncryptionKey` (32 bytes
base64 ou passphrase — ver [C1](#c1)). Fail-closed sem chave.

Migração offline de bancos plaintext existentes: reusar o padrão
`MigratePlaintext` do control (`sqlcipher_export`), exposto como subcomando
`jolt-node encrypt-database`.

**Risco/migração.** Médio. Exige CGO (a imagem já compila SQLCipher no control —
replicar toolchain no `node/Dockerfile`). Bancos existentes precisam de migração
offline única. Notas:

- Extrair `database.Open`/`MigratePlaintext` para um pacote compartilhado entre
  node e control para não duplicar.
- SQLCipher + WAL exige que o arquivo `-wal`/`-shm` também sejam cifrados; o
  driver cuida disso, mas valide `PRAGMA integrity_check` pós-migração.

**Validar.** Boot cria banco cifrado; `IsPlaintext` rejeita legado; testes de
integridade pós-migração; `hexdump` do `.db` não deve conter cabeçalho
`SQLite format 3`.

---

## <a id="c1"></a>C1 — KDF forte para a passphrase do SQLCipher

**Objetivo.** Passphrase deixar de virar chave com um único SHA-256.

**Mudança.** Em `ParseEncryptionKey`, quando a entrada não for uma chave base64
de 32 bytes, derivar com Argon2id usando um sal persistido em sidecar ao banco.

`control/internal/config/config.go`:

```go
// deriveKeyFromPassphrase aplica Argon2id sobre a passphrase com um sal durável.
// O sal fica em <dataDir>/.db.salt (0600), criado na primeira execução.
func deriveKeyFromPassphrase(passphrase, saltPath string) ([]byte, error) {
	salt, err := os.ReadFile(saltPath)
	if errors.Is(err, os.ErrNotExist) {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		if err := os.WriteFile(saltPath, salt, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(salt) != 16 {
		return nil, errors.New("db salt file is corrupted")
	}
	// m=64MiB, t=3, p=2 — parâmetros de dado em repouso (mais altos que os de login).
	return argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 2, 32), nil
}
```

`ParseEncryptionKey` passa a receber o `saltPath` e só cai no ramo Argon2id
quando a entrada não decodifica como 32 bytes base64.

**Risco/migração.** Alto se aplicado a bancos existentes: mudar a derivação
**muda a chave** e torna o banco atual ilegível. Estratégia:

1. Novos deployments: default Argon2id.
2. Existentes: exigir `encrypt-database`/rekey offline (abrir com chave antiga,
   `PRAGMA rekey` com a nova). Documentar em `docs/DISASTER_RECOVERY.md`.
3. Alternativa sem rekey: manter compatibilidade lendo o sidecar; se ausente,
   assumir derivação legada (SHA-256) e avisar para migrar.

**Recomendação primária.** Priorizar sempre a chave base64 de 32 bytes de alta
entropia — nesse caminho o KDF é irrelevante e não há migração.

**Validar.** Sal criado uma vez e reutilizado; boots subsequentes abrem o mesmo
banco; passphrase errada falha fechado.

---

## <a id="c2"></a>C2 — Separação de subchaves com HKDF

**Objetivo.** Não usar a mesma chave para o banco e para os campos AES-GCM.

**Mudança.** Derivar subchaves por finalidade a partir da chave-mestre.

```go
import "golang.org/x/crypto/hkdf"

func subKey(master []byte, label string) ([]byte, error) {
	reader := hkdf.New(sha256.New, master, nil, []byte("jolt/"+label))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// No boot:
dbKey, _   := subKey(master, "db-v1")     // vai para o SQLCipher
fieldKey, _ := subKey(master, "field-v1") // vai para security.Encrypt/Decrypt
```

`security.Encrypt/Decrypt` passam a receber `fieldKey`; o SQLCipher recebe
`dbKey`.

**Risco/migração.** Alto para bancos existentes: os campos AES-GCM já gravados
foram cifrados com a chave-mestre; após separar, decifram com a chave antiga uma
vez e recifram com `fieldKey` (rotação de campo). O `db-v1` muda a chave do
SQLCipher → exige rekey. Aplicar junto de [C1](#c1) numa única migração para não
pagar rekey duas vezes. O sufixo `-v1` prepara rotação futura.

**Validar.** Round-trip de campos com `fieldKey`; banco abre com `dbKey`;
vazamento de uma subchave não expõe a outra.

---

## <a id="c3"></a>C3 — Fingerprint de 128 bits

**Objetivo.** Elevar a margem de segundo-preimagem do âncora de trust.

**Mudança.** `node/backend/internal/infra/crypto/certificates.go:693`:

```go
sum := sha256.Sum256(raw)
return ed25519.PublicKey(raw), formatFingerprint(sum[:16]), nil // 10 → 16 bytes
```

Ajustar `formatFingerprint` para agrupar 16 bytes de forma legível (ex.: grupos
de 2 bytes separados por `:`).

**Risco/migração.** Médio. A fingerprint identifica peers já confiáveis
(`peers.Fingerprint`, `PreviousFingerprint`) e é confirmada por humanos no
pairing. Alterar o comprimento invalida o match de peers existentes. Estratégia:

1. Introduzir a fingerprint longa como **campo adicional** (`fingerprint_v2`),
   mantendo a de 80 bits durante a transição.
2. Aceitar match por qualquer das duas durante uma janela.
3. Novos pairings usam apenas a de 128 bits; migrar registros antigos ao
   reautenticar.

**Validar.** Handshake mTLS aceita peer com fingerprint nova; confirmação humana
mostra o formato novo; peers legados continuam válidos na janela.

---

## <a id="c4"></a>C4 — Fechar o furo de Origin no CSRF

**Objetivo.** Não permitir mutação sem prova de origem.

**Mudança.** `control/internal/httpapi/server.go`, middleware `csrf`:

```go
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Fallback para Referer quando o navegador omite Origin.
				origin = r.Header.Get("Referer")
			}
			if origin == "" {
				writeError(w, r, http.StatusForbidden, "missing_origin",
					"Requisição de mutação exige cabeçalho Origin ou Referer.")
				return
			}
			parsed, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(parsed.Host, r.Host) {
				writeError(w, r, http.StatusForbidden, "invalid_origin", "Origem da requisição não permitida.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
```

**Risco/migração.** Baixo. Clientes de API server-to-server (service accounts)
que hoje não mandam `Origin` passariam a falhar em mutações. Mitigar isentando
autenticação por bearer (service account) do check — o vetor CSRF só existe para
sessão por cookie:

```go
if currentActorType(r) != "service_account" { /* aplica o check */ }
```

**Validar.** Mutação por cookie sem Origin/Referer → 403; com Origin válido →
ok; service account por bearer → ok.

---

## <a id="c5"></a>C5 — Pool de leitura no SQLite

**Objetivo.** Remover o gargalo de `MaxOpenConns(1)` para leituras.

**Mudança.** Manter **um escritor** serializado e abrir um **pool de leitura**
separado (WAL permite N leitores + 1 escritor).

```go
type Store struct {
	write *sql.DB // MaxOpenConns(1), transações IMMEDIATE
	read  *sql.DB // MaxOpenConns(N), mode=ro
}

func Open(path string, key []byte) (*Store, error) {
	write, err := database.Open(path, key, false)
	if err != nil {
		return nil, err
	}
	write.SetMaxOpenConns(1)
	read, err := database.Open(path, key, true) // mode=ro
	if err != nil {
		return nil, err
	}
	read.SetMaxOpenConns(max(4, runtime.NumCPU()))
	return &Store{write: write, read: read}, nil
}
```

Roteamento: `SELECT` → `read`; `INSERT/UPDATE/DELETE`/transações → `write`.
Iniciar transações de escrita como `BEGIN IMMEDIATE` para falhar cedo em
contenção em vez de bloquear no meio.

**Risco/migração.** Médio. Exige disciplinar cada query pelo pool correto.
Cuidado com read-after-write: uma leitura logo após escrita pode não enxergar o
commit se o WAL ainda não propagou; para fluxos que exigem leitura consistente
imediata, ler pelo `write`.

**Validar.** Rodar `make acceptance` antes/depois medindo throughput de
transferências concorrentes + navegação simultânea; sem regressão de corretude
nos testes de job/claim.

---

## <a id="c6"></a>C6 — Reavaliar o componente final (TOCTOU)

**Objetivo.** Eliminar a janela em que um symlink inserido out-of-band no
componente final escape do mount durante criação.

**Mudança.** Em `resolve` com `allowMissing=true`, se o alvo já existir, tratá-lo
como no caminho normal (reavaliar o próprio componente, não só o pai):

```go
check := candidate
if allowMissing {
	if _, statErr := os.Lstat(candidate); errors.Is(statErr, fs.ErrNotExist) {
		check = filepath.Dir(candidate) // só usa o pai quando o alvo realmente não existe
	}
}
evaluated, err := filepath.EvalSymlinks(check)
```

Complementarmente, abrir destinos com `O_NOFOLLOW` (via `os.OpenFile` com a flag)
nos pontos de escrita direta, e manter o padrão temp-file + `os.Rename` atômico
(que já substitui o symlink em vez de segui-lo).

**Risco/migração.** Baixo/médio. `O_NOFOLLOW` é POSIX; em destinos que
legitimamente são symlinks a semântica muda (passa a recusar). Alinhar com o
comportamento esperado do produto (o node não expõe criação de symlink).

**Validar.** Teste: pré-criar symlink apontando para fora do mount e tentar
upload/mkdir no mesmo nome → operação não escreve fora do root.

---

## <a id="c7"></a>C7 — Trailer sentinela em erro de stat

**Objetivo.** O destino nunca interpretar ausência de trailer como sucesso.

**Mudança.** `node/backend/internal/infra/mtlsapi/server.go:84`:

```go
if finalETag, statErr := source.CurrentETag(); statErr == nil {
	w.Header().Set("X-Jolt-Final-ETag", finalETag)
} else {
	// Sinaliza explicitamente falha de revalidação da origem.
	w.Header().Set("X-Jolt-Final-ETag", "error")
}
```

No consumidor (transfers, lado destino): tratar `X-Jolt-Final-ETag` ausente ou
diferente do `ETag` inicial como **fonte alterada/indeterminada** → não publicar,
reagendar/abortar.

**Risco/migração.** Baixo. Garantir que o valor sentinela nunca colida com um
ETag real (ETags aqui são derivados de tamanho/mtime, então `"error"` é seguro;
ainda assim, prefira um prefixo reservado como `"!error"`).

**Validar.** Injetar erro de stat no fim da transferência → destino não publica e
reprocessa.

---

## <a id="c8"></a>C8 — Segredos via `*_FILE`

**Objetivo.** Ler segredos de arquivo/Docker secret em vez de env em texto claro.

**Mudança.** Helper de config compartilhado:

```go
// secretValue lê KEY_FILE (se existir) com precedência sobre KEY.
func secretValue(key string) string {
	if path := strings.TrimSpace(os.Getenv(key + "_FILE")); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return strings.TrimSpace(os.Getenv(key))
}
```

Aplicar a `CONTROL_TOWER_TOKEN`, `CONTROL_TOWER_ADMIN_PASSWORD`,
`CONTROL_TOWER_DB_ENCRYPTION_KEY` e ao novo `JOLT_DB_ENCRYPTION_KEY`. No Compose:

```yaml
secrets:
  db_key:
    file: ./secrets/db_key
services:
  jolt-control:
    secrets: [db_key]
    environment:
      CONTROL_TOWER_DB_ENCRYPTION_KEY_FILE: /run/secrets/db_key
```

**Risco/migração.** Baixo. Retrocompatível — env continua funcionando quando
`_FILE` ausente.

**Validar.** Subir com secret em arquivo; `docker inspect` não mostra o valor.

---

## <a id="c9"></a>C9 — Hardening de container

**Objetivo.** Reduzir privilégio e conter uso de recurso.

**Mudança.** `docker-compose.yml`, por serviço:

```yaml
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    # entrypoint precisa de CHOWN/SETUID/SETGID para dropar privilégio;
    # readicione apenas o necessário:
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
      - DAC_OVERRIDE
    mem_limit: 1g
    cpus: "2.0"
    pids_limit: 512
```

`read_only: true` é viável no control (escreve só no volume de dados) com um
`tmpfs: /tmp`. No node, avaliar por causa dos arquivos temporários de
transferência (que ficam no volume de dados, então `read_only` do rootfs é
possível mantendo os volumes graváveis).

**Risco/migração.** Baixo/médio. Validar que o entrypoint ainda consegue
`chown` com o conjunto reduzido de capabilities.

**Validar.** Container sobe, dropa privilégio, transfere arquivo; `capsh --print`
dentro do container mostra o conjunto reduzido.

---

## <a id="c10"></a>C10 — `SECURE_COOKIES` seguro por padrão

**Objetivo.** Não emitir cookie de sessão sem `Secure` por omissão.

**Mudança.** `control/internal/config/config.go:30`:

```go
SecureCookies: boolValue("CONTROL_TOWER_SECURE_COOKIES", true), // default true
```

Para desenvolvimento local sem TLS, exigir opt-out explícito
(`CONTROL_TOWER_SECURE_COOKIES=false`). Alternativa robusta: inferir de
`X-Forwarded-Proto=https` quando atrás de proxy confiável.

**Risco/migração.** Baixo, mas quebra login em `http://localhost` se o operador
não ajustar. Atualizar `docker-compose.yml` (deixar `false` explícito no compose
de desenvolvimento) e o README.

**Validar.** Cookie emitido com `Secure` quando default; login local documentado
com o opt-out.

---

## <a id="c11"></a>C11 — Higiene de repositório

**Objetivo.** Remover clutter e versionar o código.

**Mudança.**

```sh
rmdir backend deploy            # diretórios órfãos vazios na raiz
git add -A                      # versionar node/, control/, docs/, etc.
git commit -m "Add node, control tower, and docs"
```

Confirmar que `node/backend/` é o caminho real do node (o `backend/` da raiz é
resquício de estrutura antiga).

**Risco/migração.** Nenhum funcional.

**Validar.** `git ls-files | wc -l` reflete o projeto completo; `find backend`
não existe mais.

---

## <a id="c12"></a>C12 — Sweeper de sessões e convites

**Objetivo.** Impedir crescimento ilimitado de linhas expiradas.

**Mudança.** Método no store + ticker no boot.

`control/internal/store/store.go`:

```go
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at<=?`, now.Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
```

`control/cmd/jolt-control/main.go` (antes de aguardar sinais):

```go
janitor := time.NewTicker(1 * time.Hour)
go func() {
	defer janitor.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-janitor.C:
			if _, err := storage.DeleteExpiredSessions(ctx, now.UTC()); err != nil {
				logger.Warn("session sweep failed", "error", err)
			}
		}
	}
}()
```

Rodar uma varredura também no boot. Para pairing (lado node), adicionar
`DeletePairingTerminal(ctx, before)` que remove `expired`/`rejected`/`consumed`
antigos e agendar analogamente no node.

**Risco/migração.** Baixo. Sessões apagadas já eram inválidas na leitura;
nenhuma mudança de comportamento visível. Usar o `ctx` cancelável do processo
para o goroutine encerrar no shutdown.

**Validar.** Inserir sessão expirada, rodar sweep, confirmar remoção; goroutine
encerra no SIGTERM.

---

## <a id="f1"></a>F1 — Reancorar contenção na base real do grant

**Objetivo.** Impedir que um symlink dentro do subtree concedido leve leitura ou
escrita para fora do escopo do grant (ainda que dentro do mount).

**Causa.** `withinGrant` valida apenas o path lógico; a resolução de symlink em
`filesystem.resolve` só garante contenção na **raiz do mount**, não na base do
grant.

**Mudança.** Adicionar ao `filesystem.Service` uma resolução que exige contenção
sob uma base **real** informada, e usá-la no data-plane de peers.

`node/backend/internal/services/filesystem/service.go`:

```go
// ResolveWithinBase resolve `relative` dentro do mount e exige, adicionalmente,
// que o caminho real resultante esteja contido na base real `grantBase`
// (também relativa ao mount). Fecha o escape de escopo por symlink.
func (s *Service) ResolveWithinBase(ctx context.Context, mountID, grantBase, relative string, allowMissing bool) (string, error) {
	mount, resolved, err := s.resolve(ctx, mountID, relative, allowMissing)
	if err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(mount.LocalPath)
	if err != nil {
		return "", err
	}
	realBase, err := filepath.EvalSymlinks(filepath.Join(root, cleanRelative(grantBase)))
	if err != nil {
		return "", err
	}
	// Para criação, o alvo pode não existir: cheque o pai já resolvido.
	target := resolved
	if allowMissing {
		if parent, statErr := filepath.EvalSymlinks(filepath.Dir(resolved)); statErr == nil {
			target = filepath.Join(parent, filepath.Base(resolved))
		}
	}
	if !within(realBase, target) {
		return "", ErrTraversal
	}
	return resolved, nil
}
```

`node/backend/internal/services/transfers/service.go` — substituir os pontos que
hoje fazem `withinGrant` + `files.Open`/`Metadata` por caminhos ancorados na base
do grant:

```go
// OpenSource
sourcePath, err := withinGrant(grant.Path, relative) // mantém checagem lógica barata
if err != nil {
	return SourceFile{}, err
}
// nova checagem física contra a base real do grant:
if _, err := s.files.ResolveWithinBase(ctx, grant.MountID, grant.Path, relative, false); err != nil {
	return SourceFile{}, ErrForbidden
}
file, info, err := s.files.Open(ctx, grant.MountID, sourcePath)
```

Aplicar o mesmo em `OpenManifest` (leitura de diretório e cada item do manifesto)
e em `receiveDestination` (escrita), passando `allowMissing=true` para o destino
de escrita. No walk do manifesto, validar **cada** item resolvido, não só a raiz,
pois symlinks podem aparecer em subníveis.

**Risco/migração.** Médio. Custo extra de `EvalSymlinks` por operação; aceitável.
Mounts sem symlinks não mudam de comportamento. Grants cujo caminho concedido é o
próprio root do mount (`grant.Path == "."`) ficam idênticos ao comportamento
atual.

**Validar.** Teste: criar symlink `granted/link -> ../outside_grant` dentro do
mount; peer com grant em `granted/` recebe `403/forbidden` ao acessar
`granted/link`; acessos legítimos dentro de `granted/` seguem funcionando. Repetir
para manifesto e para escrita (`receive`).

---

## <a id="f2"></a>F2 — Limite de tamanho de upload

**Objetivo.** Impedir exaustão de disco por upload sem teto.

**Mudança.** Config `MAX_UPLOAD_BYTES` (0 = ilimitado) e aplicação no handler +
checagem de espaço livre antes de publicar.

`node/backend/internal/infra/config/config.go`: adicionar
`MaxUploadBytes int64` (parse de `MAX_UPLOAD_BYTES`, default ex.: 0 ou um teto
sensato).

`node/backend/internal/infra/httpapi/server.go`, `upload`:

```go
if s.config.MaxUploadBytes > 0 {
	if r.ContentLength > s.config.MaxUploadBytes {
		writeError(w, r, http.StatusRequestEntityTooLarge, "upload_too_large",
			"Upload excede o limite configurado.", nil)
		return
	}
	// Protege contra Content-Length ausente/mentiroso:
	r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxUploadBytes)
}
```

Opcional (defesa de disco), em `filesystem.Upload`, antes do rename, verificar
espaço livre no diretório de destino (via `syscall.Statfs`/`golang.org/x/sys`) e
retornar erro dedicado se o `written` mais uma margem exceder o disponível.

**Risco/migração.** Baixo. Retrocompatível quando `MAX_UPLOAD_BYTES=0`. Ajustar o
`MaxBytesReader` também nos caminhos de cópia inline se necessário. Documentar o
novo env em `README.md` e no Compose.

**Validar.** Upload acima do limite → `413`; upload dentro do limite → ok;
`Content-Length` falso maior que o corpo é cortado pelo `MaxBytesReader`.
