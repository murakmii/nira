package http

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

type testDirServer struct {
	addr string
	port int
}

func newTestDirServer(sv *httptest.Server) *testDirServer {
	u, _ := url.Parse(sv.URL)
	addr := strings.Split(u.Host, ":")[0]
	port, _ := strconv.Atoi(u.Port())

	return &testDirServer{addr: addr, port: port}
}

func (t *testDirServer) Addr() string { return t.addr }
func (t *testDirServer) DirPort() int { return t.port }

var _ DirectoryServerSpecifier = (*testDirServer)(nil)

func TestClientImpl_Download(t *testing.T) {
	stubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("want method 'GET', got %s", r.Method)
		}
		if r.URL.Path != "/foo/bar" {
			t.Errorf("want path '/foo/bar', got %s", r.URL.Path)
		}
		if r.Header.Get("Accept-Encoding") != "gzip" {
			t.Errorf("want 'Accept-Encoding: gzip', got %s", r.Header.Get("Accept-Encoding"))
		}
		if r.Header.Get("User-Agent") != "nira" {
			t.Errorf("want 'User-Agent: nira', got %s", r.Header.Get("User-Agent"))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("this is test response"))
	}))
	defer stubServer.Close()

	got := bytes.NewBuffer(nil)
	sut := BuildClient("nira")
	if err := sut.Download(newTestDirServer(stubServer), "/foo/bar", got); err != nil {
		t.Errorf("want no error, got %v", err)
		return
	}

	if got.String() != "this is test response" {
		t.Errorf("want 'this is test response', got %s", got.String())
	}
}

func TestClientImpl_DownloadIfFailed(t *testing.T) {
	stubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer stubServer.Close()

	sut := BuildClient("nira")
	err := sut.Download(newTestDirServer(stubServer), "/foo/bar", bytes.NewBuffer(nil))
	if err == nil {
		t.Errorf("want error, got nil")
	} else if err.Error() != "host returned unexpected status code: 403" {
		t.Errorf("want 'host returned unexpected status code: 403' error, got %v", err)
	}
}
