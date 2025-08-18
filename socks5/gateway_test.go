package socks5

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/murakmii/nira/log"
	"github.com/murakmii/nira/socks5/connector"
	"golang.org/x/net/proxy"
)

func TestGateway_Listen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hello, socks5!"))
	}))
	defer server.Close()

	sut := BuildGateway("127.0.0.1:30000", log.NewLogger(log.DebugLog, os.Stdout), connector.TCP)
	stopped := make(chan struct{})

	defer func() {
		sut.Stop()
		<-stopped
	}()

	go func() {
		sut.Listen()
		close(stopped)
	}()

	socks5Proxy, err := proxy.SOCKS5("tcp4", sut.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	client := http.Client{Transport: &http.Transport{Dial: socks5Proxy.Dial}}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Errorf("failed to request server: %s", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("failed to read response body: %s", err)
		return
	}

	if string(body) != "hello, socks5!" {
		t.Errorf("got body = '%q', want = 'hello'", string(body))
	}
}
