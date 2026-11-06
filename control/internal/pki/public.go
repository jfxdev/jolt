package pki

import (
	"html/template"
	"net/http"
)

// PublicHandler serves what a person or an agent needs before it trusts the
// Control Tower: the public root certificate and its fingerprint. It answers
// only to GET and HEAD, carries nothing private and sets no cookie, so it is
// safe to serve over plain HTTP.
func PublicHandler(m *Manager) http.Handler {
	mux := http.NewServeMux()
	serve := func(w http.ResponseWriter, r *http.Request, fn func(http.ResponseWriter)) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		root := m.RootPEM()
		if len(root) == 0 {
			http.Error(w, "the certificate authority is not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
		if r.Method == http.MethodHead {
			w = headOnly{w}
		}
		fn(w)
	}
	pemHandler := func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", `attachment; filename="jolt-root-ca.pem"`)
			_, _ = w.Write(m.RootPEM())
		})
	}
	mux.HandleFunc("/ca.pem", pemHandler)
	mux.HandleFunc("/.well-known/jolt/ca.pem", pemHandler)
	mux.HandleFunc("/ca/fingerprint", func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte(m.RootFingerprint() + "\n"))
		})
	})
	mux.HandleFunc("/ca", func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = page.Execute(w, struct{ Fingerprint, Plain string }{DisplayFingerprint(m.RootFingerprint()), m.RootFingerprint()})
		})
	})
	return mux
}

// headOnly drops the body, so HEAD answers with the headers GET would send.
type headOnly struct{ http.ResponseWriter }

func (headOnly) Write(p []byte) (int, error) { return len(p), nil }

var page = template.Must(template.New("ca").Parse(`<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Certificado raiz do Jolt</title>
<style>
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--muted:#555;--line:#d4d4d4;--code:#f3f3f3}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#ececec;--muted:#a3a3a3;--line:#333;--code:#1f1f1f}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:46rem;margin:0 auto;padding:2rem 16px}
code,pre{background:var(--code);border-radius:6px;font-family:ui-monospace,monospace}
code{padding:.1rem .3rem}pre{padding:.75rem;overflow-x:auto}
.fingerprint{word-break:break-all;font-family:ui-monospace,monospace;border:1px solid var(--line);border-radius:8px;padding:.75rem}
a.button{display:inline-block;margin:.5rem 0;padding:.6rem 1rem;border:1px solid var(--fg);border-radius:8px;color:var(--fg);text-decoration:none}
h1,h2{line-height:1.2}p,li{color:var(--muted)}h2{margin-top:2rem}
</style></head><body><main>
<h1>Certificado raiz do Jolt</h1>
<p>Este Control Tower usa uma autoridade de certificação própria. Instale a raiz abaixo uma vez em cada dispositivo para o navegador deixar de avisar. Nada mais depende disso.</p>
<p><a class="button" href="/ca.pem" download>Baixar jolt-root-ca.pem</a></p>
<h2>Confira antes de instalar</h2>
<p>O fingerprint SHA-256 precisa ser o mesmo que o administrador vê no Control Tower, em Segurança. Compare por outro canal; esta página chegou por HTTP simples.</p>
<p class="fingerprint">{{.Fingerprint}}</p>
<h2>Como instalar</h2>
<ul>
<li><strong>macOS:</strong> abra o arquivo, adicione ao chaveiro Sistema, abra o item e defina Confiar como <em>Sempre confiar</em>.</li>
<li><strong>Windows:</strong> em um terminal de administrador, <code>certutil -addstore -f ROOT jolt-root-ca.pem</code>.</li>
<li><strong>Linux:</strong> copie para <code>/usr/local/share/ca-certificates/jolt-root-ca.crt</code> e execute <code>sudo update-ca-certificates</code>. O Firefox usa o repositório próprio dele.</li>
<li><strong>Agentes e scripts:</strong> aponte o cliente para o arquivo, por exemplo <code>curl --cacert jolt-root-ca.pem</code>, e confira o fingerprint antes.</li>
</ul>
<h2>Verificar sem confiar nesta página</h2>
<pre>openssl x509 -in jolt-root-ca.pem -noout -fingerprint -sha256</pre>
</main></body></html>
`))
