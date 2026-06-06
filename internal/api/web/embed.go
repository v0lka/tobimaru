// Package web embeds the React + Vite single-page application that serves
// as the Tobimaru dashboard. The compiled assets are produced by `make web`
// (or directly by `cd web && npm run build`) and committed to the repository
// so that contributors who only work on Go can build the binary without
// installing Node.js.
//
// When the dist tree is missing or empty (for example in fresh clones
// before `make web` runs), Handler still produces a 200 response with a
// minimal HTML placeholder so that operators can confirm the API is live.
package web

import (
	"embed"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// distRoot is the directory inside distFS that contains index.html.
const distRoot = "dist"

// indexFile is the SPA entry point used for any non-asset route.
const indexFile = "index.html"

// htmlContentType is the Content-Type sent for index.html and the placeholder.
const htmlContentType = "text/html; charset=utf-8"

// placeholderHTML is served when web/dist/index.html is missing. It tells
// the operator how to rebuild the SPA so the dashboard becomes available.
const placeholderHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Tobimaru WiFi Watchdog</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         max-width: 40rem; margin: 4rem auto; padding: 0 1rem; color: #222; }
  code { background: #f4f4f4; padding: 0.1rem 0.3rem; border-radius: 0.2rem; }
  pre  { background: #f4f4f4; padding: 1rem; border-radius: 0.4rem; overflow-x: auto; }
</style>
</head>
<body>
  <h1>Tobimaru WiFi Watchdog</h1>
  <p>The HTTP API is running. The web dashboard bundle has not been built yet.</p>
  <p>Build it with:</p>
  <pre>make web</pre>
  <p>Then restart the daemon. The API endpoints under <code>/api/</code> are
     already serving requests.</p>
</body>
</html>
`

// Handler returns an http.Handler that serves the embedded SPA.
//
// Routing rules:
//   - Requests to /assets/* are served as static files with strong caching.
//   - Requests to /favicon.ico (and similar known root files) are served
//     directly from the dist tree if present.
//   - Every other GET falls back to index.html so the SPA's client-side
//     router can match it. Requests for missing static asset files return
//     404 instead of falling back, so the SPA never sees the wrong MIME.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, distRoot)
	if err != nil {
		// Should never happen given the embed directive above; degrade
		// to placeholder.
		return http.HandlerFunc(servePlaceholder)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(r.URL.Path)
		if clean == "/" || clean == "" {
			serveIndex(w, r, sub)
			return
		}
		// Strip leading slash for fs.Sub lookups.
		name := strings.TrimPrefix(clean, "/")

		// /assets/* → strong caching, 404 on miss (do not fall back to SPA).
		if strings.HasPrefix(name, "assets/") {
			f, err := sub.Open(name)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			defer f.Close()
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			http.ServeFileFS(w, r, sub, name)
			return
		}

		// Direct file in dist (favicon.ico, robots.txt, etc.).
		if f, err := sub.Open(name); err == nil {
			f.Close()
			http.ServeFileFS(w, r, sub, name)
			return
		}

		// SPA fallback — serve index.html so client-side router resolves the path.
		serveIndex(w, r, sub)
	})
}

// IndexHTML returns the embedded index.html bytes, or the placeholder HTML
// when no built bundle is present. Useful for inline rendering by the API
// server's NotFound handler.
func IndexHTML() (body []byte, contentType string) {
	sub, err := fs.Sub(distFS, distRoot)
	if err != nil {
		return []byte(placeholderHTML), htmlContentType
	}
	f, err := sub.Open(indexFile)
	if err != nil {
		return []byte(placeholderHTML), htmlContentType
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return []byte(placeholderHTML), htmlContentType
	}
	return data, htmlContentType
}

// serveIndex writes index.html (or the placeholder when missing).
func serveIndex(w http.ResponseWriter, _ *http.Request, sub fs.FS) {
	f, err := sub.Open(indexFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			servePlaceholder(w, nil)
			return
		}
		http.Error(w, "failed to open index.html", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "failed to read index.html", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", htmlContentType)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}

// servePlaceholder writes the placeholder HTML.
func servePlaceholder(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", htmlContentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(placeholderHTML))
}
