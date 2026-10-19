// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trust_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	test "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/testdata"
	"github.com/google/go-sev-guest/verify/trust"
)

func TestRetryHTTPSGetter(t *testing.T) {
	testCases := map[string]struct {
		getter        *test.Getter
		timeout       time.Duration
		maxRetryDelay time.Duration
	}{
		"immediate success": {
			getter: &test.Getter{
				Responses: map[string][]test.GetResponse{
					"https://fetch.me": {
						{
							Occurrences: 1,
							Body:        []byte("content"),
							Error:       nil,
						},
					},
				},
			},
			timeout:       time.Second,
			maxRetryDelay: time.Millisecond,
		},
		"second success": {
			getter: &test.Getter{
				Responses: map[string][]test.GetResponse{
					"https://fetch.me": {
						{
							Occurrences: 1,
							Body:        []byte(""),
							Error:       errors.New("fail"),
						},
						{
							Occurrences: 1,
							Body:        []byte("content"),
							Error:       nil,
						},
					},
				},
			},
			timeout:       time.Second,
			maxRetryDelay: time.Millisecond,
		},
		"third success": {
			getter: &test.Getter{
				Responses: map[string][]test.GetResponse{
					"https://fetch.me": {
						{
							Occurrences: 2,
							Body:        []byte(""),
							Error:       errors.New("fail"),
						},
						{
							Occurrences: 1,
							Body:        []byte("content"),
							Error:       nil,
						},
					},
				},
			},
			timeout:       time.Second,
			maxRetryDelay: time.Millisecond,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			r := &trust.RetryHTTPSGetter{
				Timeout:       tc.timeout,
				MaxRetryDelay: tc.maxRetryDelay,
				Getter:        tc.getter,
			}

			body, err := r.Get("https://fetch.me")
			if !bytes.Equal(body, []byte("content")) {
				t.Errorf("expected '%s' but got '%s'", "content", body)
			}
			if err != nil {
				t.Errorf("expected no error, but got %s", err.Error())
			}
			tc.getter.Done(t)
		})
	}
}

func TestRetryHTTPSGetterAllFail(t *testing.T) {
	testGetter := &test.Getter{
		Responses: map[string][]test.GetResponse{
			"https://fetch.me": {
				{
					Occurrences: 1,
					Body:        []byte(""),
					Error:       errors.New("fail"),
				},
			},
		},
	}
	r := &trust.RetryHTTPSGetter{
		Timeout:       1 * time.Millisecond,
		MaxRetryDelay: 1 * time.Millisecond,
		Getter:        testGetter,
	}

	body, err := r.Get("https://fetch.me")
	if !bytes.Equal(body, []byte("")) {
		t.Errorf("expected empty body but got %q", body)
	}
	if err == nil {
		t.Errorf("expected error, but got none")
	}
	testGetter.Done(t)
}

func TestRetryHTTPSGetterContext(t *testing.T) {
	testGetter := &test.Getter{
		Responses: map[string][]test.GetResponse{
			"https://fetch.me": {
				{
					Occurrences: 1,
					Body:        []byte("content"),
					Error:       nil,
				},
			},
		},
	}
	r := &trust.RetryHTTPSGetter{
		MaxRetryDelay: 1 * time.Millisecond,
		Getter:        testGetter,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body, err := r.GetContext(ctx, "https://fetch.me")
	if !bytes.Equal(body, []byte("")) {
		t.Errorf("expected empty body but got %q", body)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected error %q, but got %q", context.Canceled, err)
	}
}

func TestGetProductChainForRaceDetector(t *testing.T) {
	testGetter := &test.Getter{
		Responses: map[string][]test.GetResponse{
			"https://kdsintf.amd.com/vcek/v1/test/cert_chain": {
				{
					Occurrences: 2,
					Body:        trust.AskArkMilanVcekBytes,
				},
			},
		},
	}

	// run GetProductChain concurrently to see if the race detector is triggered.
	errCh := make(chan error)
	go func() {
		_, err := trust.GetProductChain("test", abi.VcekReportSigner, testGetter)
		errCh <- err
	}()

	go func() {
		_, err := trust.GetProductChain("test", abi.VcekReportSigner, testGetter)
		errCh <- err
	}()

	var err error
	for i := 0; i < 2; i++ {
		err = errors.Join(err, <-errCh)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

type recordingGetter struct {
	getCalls int
}

func (r *recordingGetter) Get(_ string) ([]byte, error) {
	r.getCalls++
	return []byte{}, nil
}

type recordingContextGetter struct {
	recordingGetter
	getContextCalls int
}

func (r *recordingContextGetter) GetContext(_ context.Context, _ string) ([]byte, error) {
	r.getContextCalls++
	return []byte{}, nil
}

func TestGetWith(t *testing.T) {
	url := ""
	t.Run("HTTPSGetter uses Get", func(t *testing.T) {
		contextGetter := recordingContextGetter{}
		if _, err := trust.GetWith(context.Background(), &contextGetter.recordingGetter, url); err != nil {
			t.Fatalf("trust.GetWith returned an unexpected error: %v", err)
		}
		if contextGetter.getContextCalls != 0 {
			t.Errorf("wrong number of calls to GetContext: got %d, want 0", contextGetter.getContextCalls)
		}
		if contextGetter.recordingGetter.getCalls != 1 {
			t.Errorf("wrong number of calls to Get: got %d, want 1", contextGetter.getCalls)
		}
	})
	t.Run("ContextHTTPSGetter uses GetContext", func(t *testing.T) {
		contextGetter := recordingContextGetter{}
		if _, err := trust.GetWith(context.Background(), &contextGetter, url); err != nil {
			t.Fatalf("trust.GetWith returned an unexpected error: %v", err)
		}
		if contextGetter.getContextCalls != 1 {
			t.Errorf("wrong number of calls to GetContext: got %d, want 1", contextGetter.getContextCalls)
		}
		if contextGetter.recordingGetter.getCalls != 0 {
			t.Errorf("wrong number of calls to Get: got %d, want 0", contextGetter.getCalls)
		}
	})

}

// statusServer serves the given status codes in order, one per request, and then repeats the
// last one. A 200 response has body "content". It returns the server and a request counter.
func statusServer(t *testing.T, statuses ...int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i := int(calls.Add(1)) - 1
		if i >= len(statuses) {
			i = len(statuses) - 1
		}
		w.WriteHeader(statuses[i])
		if statuses[i] == http.StatusOK {
			w.Write([]byte("content"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestSimpleHTTPSGetterStatusError(t *testing.T) {
	srv, _ := statusServer(t, http.StatusNotFound)
	_, err := (&trust.SimpleHTTPSGetter{}).Get(srv.URL)
	var statusErr *trust.HTTPStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Get() = %v, want *trust.HTTPStatusError", err)
	}
	if statusErr.StatusCode != http.StatusNotFound || statusErr.URL != srv.URL {
		t.Errorf("Get() error = %+v, want URL %q and status %d", statusErr, srv.URL, http.StatusNotFound)
	}
	if want := fmt.Sprintf("failed to retrieve '%s' status 404", srv.URL); err.Error() != want {
		t.Errorf("Get() error text = %q, want %q", err.Error(), want)
	}
}

func TestSimpleHTTPSGetterBodyLimit(t *testing.T) {
	old := trust.MaxResponseBytes
	trust.MaxResponseBytes = 16
	t.Cleanup(func() { trust.MaxResponseBytes = old })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size := 16
		if r.URL.Path == "/large" {
			size = 1 << 20
		}
		w.Write(bytes.Repeat([]byte{'a'}, size))
	}))
	t.Cleanup(srv.Close)

	getter := &trust.SimpleHTTPSGetter{}
	if body, err := getter.Get(srv.URL + "/limit"); err != nil || len(body) != 16 {
		t.Errorf("Get(body at limit) = %d bytes, %v; want 16 bytes, nil", len(body), err)
	}
	if body, err := getter.Get(srv.URL + "/large"); err == nil {
		t.Errorf("Get(body over limit) = %d bytes, nil; want error", len(body))
	}
}

func TestRetryHTTPSGetterStatusPolicy(t *testing.T) {
	tcs := []struct {
		name       string
		statuses   []int
		timeout    time.Duration
		wantErr    bool
		wantStatus int
		wantCalls  int32 // exact count; 0 means "more than one"
	}{
		{name: "404 is permanent", statuses: []int{http.StatusNotFound}, timeout: 5 * time.Second, wantErr: true, wantStatus: http.StatusNotFound, wantCalls: 1},
		{name: "400 is permanent", statuses: []int{http.StatusBadRequest}, timeout: 5 * time.Second, wantErr: true, wantStatus: http.StatusBadRequest, wantCalls: 1},
		{name: "429 then 200 retries", statuses: []int{http.StatusTooManyRequests, http.StatusOK}, timeout: 5 * time.Second, wantCalls: 2},
		{name: "503 then 200 retries", statuses: []int{http.StatusServiceUnavailable, http.StatusOK}, timeout: 5 * time.Second, wantCalls: 2},
		{name: "500 retries until timeout", statuses: []int{http.StatusInternalServerError}, timeout: 100 * time.Millisecond, wantErr: true, wantStatus: http.StatusInternalServerError},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := statusServer(t, tc.statuses...)
			r := &trust.RetryHTTPSGetter{
				Timeout:       tc.timeout,
				MaxRetryDelay: time.Millisecond,
				Getter:        &trust.SimpleHTTPSGetter{},
			}
			start := time.Now()
			body, err := r.Get(srv.URL)
			elapsed := time.Since(start)

			if !tc.wantErr {
				if err != nil || string(body) != "content" {
					t.Fatalf("Get() = %q, %v; want \"content\", nil", body, err)
				}
			} else {
				var statusErr *trust.HTTPStatusError
				if !errors.As(err, &statusErr) || statusErr.StatusCode != tc.wantStatus {
					t.Fatalf("Get() = %v, want *trust.HTTPStatusError with status %d", err, tc.wantStatus)
				}
			}
			got := calls.Load()
			if tc.wantCalls != 0 && got != tc.wantCalls {
				t.Errorf("server got %d requests, want %d", got, tc.wantCalls)
			}
			if tc.wantCalls == 0 && got < 2 {
				t.Errorf("server got %d requests, want more than 1", got)
			}
			if tc.wantCalls == 1 && elapsed > time.Second {
				t.Errorf("Get() took %v for a permanent error, want an immediate return", elapsed)
			}
		})
	}
}

func TestRetryHTTPSGetterContextErrorNotRetried(t *testing.T) {
	var calls atomic.Int32
	getter := contextErrGetter{calls: &calls}
	r := &trust.RetryHTTPSGetter{
		Timeout:       5 * time.Second,
		MaxRetryDelay: time.Millisecond,
		Getter:        getter,
	}
	_, err := r.Get("https://fetch.me")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Get() = %v, want context.Canceled", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("getter called %d times, want 1", got)
	}
}

// contextErrGetter always fails with context.Canceled, as an inner getter does when its own
// context is canceled.
type contextErrGetter struct {
	calls *atomic.Int32
}

func (g contextErrGetter) Get(_ string) ([]byte, error) {
	g.calls.Add(1)
	return nil, fmt.Errorf("request failed: %w", context.Canceled)
}

// Ensure that the HTTPSGetters implement the expected interfaces.
var (
	_ = trust.HTTPSGetter(&trust.SimpleHTTPSGetter{})
	_ = trust.HTTPSGetter(&trust.RetryHTTPSGetter{})
	_ = trust.ContextHTTPSGetter(&trust.SimpleHTTPSGetter{})
	_ = trust.ContextHTTPSGetter(&trust.RetryHTTPSGetter{})
)

func FuzzParseCert(f *testing.F) {
	vcekPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: testdata.VcekBytes,
	})
	f.Add([]byte{})
	f.Add(testdata.VcekBytes)
	f.Add(vcekPEM)
	f.Add(append(append([]byte{}, vcekPEM...), vcekPEM...))
	f.Add(append(append([]byte{}, vcekPEM...), "trailing"...))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = trust.ParseCert(data)
	})
}
