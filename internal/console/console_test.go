package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The console shares a listener with the API, so the one thing it must never do
// is answer for the API. A client that gets HTML where it expected JSON reports
// a parse error, which is a long way round to "no such route".
func TestConsoleNeverAnswersForTheAPI(t *testing.T) {
	h := Handler()
	for _, path := range []string{"/v1/campaigns", "/v1/nope", "/v1/"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d; the console is claiming an API path", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "<html") {
			t.Errorf("%s was answered with HTML", path)
		}
	}
}

// A build without the console says so, and says how to get one. The person who
// hits this expected a console; that it is missing is the answer they need.
func TestABuildWithoutTheConsoleExplainsItself(t *testing.T) {
	if Built() {
		t.Skip("this build carries the console")
	}
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("a console-less build answered %d, want 503", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "make build-console") {
		t.Errorf("the page does not say how to build the console:\n%s", body)
	}
	if !strings.Contains(body, "xfuzz") {
		t.Error("the page does not say that the CLI reaches everything the console would")
	}
}
