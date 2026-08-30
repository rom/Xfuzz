// Package console serves the web console from inside the binary.
//
// ASR-0015 wants one artifact: a build of Xfuzz that needs a directory of
// assets beside it is a build somebody will eventually deploy without them, and
// an air-gapped install cannot fetch what is missing. So the console is
// compiled to static files and embedded (ADR-0011) — no CDN, no runtime asset
// fetch, no external fonts.
//
// Building it needs Node, and building Xfuzz must not. The assets are behind
// the `console` build tag: `go build ./...` produces a working daemon whose
// console says how to build it, and `make build-console` produces the one that
// carries it. That keeps the Go toolchain sufficient for everything except the
// console itself.
package console

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// Handler serves the console, falling back to its entry document.
//
// The fallback is what makes deep links work. A console is a single page with
// client-side routing, so /campaigns/nightly is a path the client understands
// and the server has never heard of; serving index.html for anything that is
// not a file lets somebody paste a link to a finding and land on it.
//
// Anything under /v1 is not ours and is refused here rather than answered with
// a page: an API client that gets HTML where it expected JSON reports a parse
// error, which is a much longer way round to "no such route".
func Handler() http.Handler {
	assets, err := Assets()
	if err != nil {
		return notBuilt(err)
	}
	files := http.FileServer(http.FS(assets))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean("/" + r.URL.Path)
		if IsAPIPath(clean) {
			http.NotFound(w, r)
			return
		}
		if clean != "/" {
			if f, ferr := assets.Open(strings.TrimPrefix(clean, "/")); ferr == nil {
				f.Close()
				// A hashed asset name is a promise that its content never
				// changes, so it can be cached for as long as the browser
				// likes. The entry document is not, and is served below with
				// no such promise.
				if hashedAsset(clean) {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		serveIndex(w, r, assets)
	})
}

// serveIndex writes the entry document for a client-side route.
func serveIndex(w http.ResponseWriter, r *http.Request, assets fs.FS) {
	b, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		http.Error(w, "the console is not built into this binary", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Never cached: it names the hashed assets, so a stale one points a browser
	// at files that no longer exist and the console fails to start with nothing
	// on screen to say why.
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "index.html", indexModTime, strings.NewReader(string(b)))
}

// IsAPIPath reports whether a path belongs to the API rather than the console.
//
// The bare "/v1/" is the case worth naming: path.Clean turns it into "/v1",
// which does not carry the "/v1/" prefix, so a prefix test alone hands it to
// the console and a client asking for the API root gets a web page.
func IsAPIPath(clean string) bool {
	return clean == apiRoot || strings.HasPrefix(clean, apiRoot+"/")
}

// apiRoot is the prefix the API owns. The console owns everything else.
const apiRoot = "/v1"

// hashedAsset reports whether a path names a build artefact whose content is
// pinned by its name, which is what Vite emits into /assets.
func hashedAsset(p string) bool {
	return strings.HasPrefix(p, "/assets/")
}

// notBuilt answers when the binary carries no console.
//
// A page rather than a bare 404, because the person who hits this is usually
// somebody who built with `go build` and expected a console: the useful answer
// is how to get one, not that the path does not exist.
func notBuilt(err error) http.Handler {
	body := []byte(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Xfuzz</title>
<style>
  body { font: 14px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace;
         margin: 4rem auto; max-width: 42rem; padding: 0 1.5rem; }
  code { background: rgba(127,127,127,.15); padding: .1em .35em; border-radius: 3px; }
</style></head><body>
<h1>The console is not built into this binary</h1>
<p>The API is running and complete: every capability the console has is a route
on it, and <code>xfuzz</code> reaches all of them.</p>
<p>To build the console:</p>
<pre>make build-console</pre>
<p>That runs the TypeScript build and compiles the daemon with the
<code>console</code> tag, which is what embeds the result.</p>
</body></html>
`)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsAPIPath(path.Clean("/" + r.URL.Path)) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(body)
	})
}

// Built reports whether this binary carries the console.
func Built() bool {
	_, err := Assets()
	return err == nil
}
