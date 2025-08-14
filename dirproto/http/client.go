package http

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// References:
// https://spec.torproject.org/dir-spec/client-operation.html#retrying-failed-downloads
// https://spec.torproject.org/dir-spec/standards-compliance.html
type (
	Client interface {
		Download(sv DirectoryServerSpecifier, path string, to io.Writer) error
	}

	DirectoryServerSpecifier interface {
		Addr() string
		DirPort() int
	}

	clientImpl struct {
		hc        *http.Client
		userAgent string
	}
)

func BuildClient(userAgent string) Client {
	return &clientImpl{
		hc: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        5,
				MaxIdleConnsPerHost: 1,
				IdleConnTimeout:     10 * time.Second,
				DisableCompression:  false, // Use gzip automatically
			},
			Timeout: 10 * time.Second,
		},
		userAgent: userAgent,
	}
}

// TODO: retrying with exponential backoff
func (c *clientImpl) Download(sv DirectoryServerSpecifier, path string, bodyTo io.Writer) error {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:%d%s", sv.Addr(), sv.DirPort(), path), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("host returned unexpected status code: %d", resp.StatusCode)
	}

	if _, err = io.Copy(bodyTo, resp.Body); err != nil {
		return err
	}
	return nil
}
