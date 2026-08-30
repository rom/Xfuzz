//go:build console

package console

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Air-gap: ASR-0015 wants one artifact, so nothing the console loads may come
// from the network. A CDN script or an external font turns an install with no
// route out into a console that hangs and then renders wrong.
func TestTheBundleFetchesNothingExternal(t *testing.T) {
	assets, err := Assets()
	if err != nil {
		t.Fatal(err)
	}
	err = fs.WalkDir(assets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := fs.ReadFile(assets, path)
		if rerr != nil {
			return rerr
		}
		for _, host := range []string{
			"https://", "http://fonts.", "//cdn.", "//unpkg.", "//cdnjs.",
		} {
			if i := strings.Index(string(b), host); i >= 0 {
				// The SVG namespace is a URL that is never fetched: it is an
				// XML identifier and the only external-looking string a
				// correct bundle contains.
				if strings.HasPrefix(string(b[i:]), "http://www.w3.org/") {
					continue
				}
				t.Errorf("%s references %s, which an air-gapped install cannot reach", path, host)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Deep links have to work: a link to a finding is how one person shows another
// what they found, and the server has never heard of that path.
func TestDeepLinksServeTheConsole(t *testing.T) {
	h := Handler()
	for _, path := range []string{"/", "/campaign/nightly", "/finding/nightly/3"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s answered %d", path, w.Code)
		}
		if !strings.Contains(w.Body.String(), `id="app"`) {
			t.Errorf("%s did not serve the console's entry document", path)
		}
	}
}

// A hashed asset name is a promise its content never changes; the entry
// document is not, and a cached one points at files that no longer exist.
func TestCachingMatchesWhatTheNameGuarantees(t *testing.T) {
	assets, err := Assets()
	if err != nil {
		t.Fatal(err)
	}
	var asset string
	_ = fs.WalkDir(assets, "assets", func(path string, d fs.DirEntry, _ error) error {
		if !d.IsDir() && asset == "" {
			asset = "/" + path
		}
		return nil
	})
	if asset == "" {
		t.Fatal("the bundle emitted no hashed assets")
	}

	h := Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, asset, nil))
	if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Errorf("%s is served with Cache-Control %q; a hashed name may be cached forever", asset, got)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("the entry document is served with Cache-Control %q; a stale one names assets that are gone", got)
	}
}
