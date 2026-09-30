package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// A stand-in bundle: an entry document, one hashed asset, one unhashed file.
// The rules are about names and paths, so a real Vite build is not needed to
// check them — and this runs in a build without the console tag too.
func fakeBundle() fstest.MapFS {
	return fstest.MapFS{
		"index.html":              {Data: []byte(`<!doctype html><div id="app"></div>`)},
		"assets/index-abc123.js":  {Data: []byte(`console.log("hi")`)},
		"assets/index-abc123.css": {Data: []byte(`body{}`)},
		"favicon.svg":             {Data: []byte(`<svg/>`)},
	}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func TestDeepLinksFallBackToTheEntryDocument(t *testing.T) {
	// A link to a finding is a path the server has never heard of. It has to
	// serve the console, which then reads the path itself.
	h := handlerFor(fakeBundle())
	for _, path := range []string{"/", "/campaign/nightly", "/finding/nightly/3", "/no/such/thing.html"} {
		w := get(t, h, path)
		if w.Code != http.StatusOK {
			t.Errorf("%s answered %d", path, w.Code)
		}
		if !strings.Contains(w.Body.String(), `id="app"`) {
			t.Errorf("%s did not serve the entry document: %q", path, w.Body.String())
		}
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s served the entry document with Cache-Control %q; a cached one names assets that no longer exist", path, cc)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s served as %q", path, ct)
		}
	}
}

func TestARealFileIsServedAsItself(t *testing.T) {
	h := handlerFor(fakeBundle())

	w := get(t, h, "/assets/index-abc123.js")
	if w.Code != http.StatusOK || w.Body.String() != `console.log("hi")` {
		t.Errorf("the asset was not served: %d %q", w.Code, w.Body.String())
	}
	// Hashed: its name pins its content, so it may be cached for ever.
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("a hashed asset has Cache-Control %q", cc)
	}

	// Not hashed: served, but with no such promise.
	w = get(t, h, "/favicon.svg")
	if w.Code != http.StatusOK || w.Body.String() != `<svg/>` {
		t.Errorf("favicon: %d %q", w.Code, w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); strings.Contains(cc, "immutable") {
		t.Errorf("an unhashed file was marked immutable: %q", cc)
	}
}

func TestTheAPIIsNeverAnsweredByAnyBundle(t *testing.T) {
	// The tagged test checks this against the real bundle; this checks it is
	// the handler's rule and not an accident of what the bundle contains —
	// including for a file the bundle really does hold under that prefix.
	bundle := fakeBundle()
	bundle["v1/openapi.json"] = &fstest.MapFile{Data: []byte(`{}`)}
	h := handlerFor(bundle)
	for _, path := range []string{"/v1", "/v1/", "/v1/openapi.json", "/v1/campaigns/x", "/../v1/info"} {
		w := get(t, h, path)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d; the console is claiming an API path", path, w.Code)
		}
	}
}

func TestIsAPIPathIsExact(t *testing.T) {
	for p, want := range map[string]bool{
		"/v1": true, "/v1/": true, "/v1/info": true,
		"/v10": false, "/v1x": false, "/": false, "/campaign/v1": false, "/api/v1": false,
	} {
		if got := IsAPIPath(p); got != want {
			t.Errorf("IsAPIPath(%q) = %v, want %v", p, got, want)
		}
	}
	if !hashedAsset("/assets/x.js") || hashedAsset("/index.html") || hashedAsset("/assets") {
		t.Error("hashedAsset is wrong about a path")
	}
}

func TestBuiltAgreesWithAssets(t *testing.T) {
	_, err := Assets()
	if Built() != (err == nil) {
		t.Errorf("Built() = %v but Assets() = %v", Built(), err)
	}
}
