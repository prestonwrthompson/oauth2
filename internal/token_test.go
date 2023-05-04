// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRetrieveToken_InParams(t *testing.T) {
	ResetAuthCache()
	const clientID = "client-id"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.FormValue("client_id"), clientID; got != want {
			t.Errorf("client_id = %q; want %q", got, want)
		}
		if got, want := r.FormValue("client_secret"), ""; got != want {
			t.Errorf("client_secret = %q; want empty", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	}))
	defer ts.Close()
	_, err := RetrieveToken(context.Background(), clientID, "", ts.URL, url.Values{}, AuthStyleInParams, FormUrlEncodingStyleDisabled)
	if err != nil {
		t.Errorf("RetrieveToken = %v; want no error", err)
	}
}

func TestRetrieveToken_FormUrlEncodingDisabled(t *testing.T) {
	ResetAuthCache()
	const clientID = "client/id"
	const clientSecret = "client/secret"
	auth := clientID + ":" + clientSecret
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Basic "+encodedAuth; got != want {
			t.Errorf("RetrieveToken autorization header = %q; want %q", got, want)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("RetrieveToken decoding body = %v; want no error", err)
		}
		if string(body) != "" {
			t.Errorf("RetrieveToken body = %v; want empty", err)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	}))
	defer ts.Close()
	_, err := RetrieveToken(context.Background(), clientID, clientSecret, ts.URL, url.Values{}, AuthStyleInHeader, FormUrlEncodingStyleDisabled)
	if err != nil {
		t.Errorf("RetrieveToken = %v; want no error", err)
	}
}

func TestRetrieveTokenWithContexts(t *testing.T) {
	ResetAuthCache()
	const clientID = "client-id"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	}))
	defer ts.Close()

	_, err := RetrieveToken(context.Background(), clientID, "", ts.URL, url.Values{}, AuthStyleUnknown, FormUrlEncodingStyleDisabled)
	if err != nil {
		t.Errorf("RetrieveToken (with background context) = %v; want no error", err)
	}

	retrieved := make(chan struct{})
	cancellingts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-retrieved
	}))
	defer cancellingts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = RetrieveToken(ctx, clientID, "", cancellingts.URL, url.Values{}, AuthStyleUnknown, FormUrlEncodingStyleDisabled)
	close(retrieved)
	if err == nil {
		t.Errorf("RetrieveToken (with cancelled context) = nil; want error")
	}
}

func TestExpiresInUpperBound(t *testing.T) {
	var e expirationTime
	if err := e.UnmarshalJSON([]byte(fmt.Sprint(int64(math.MaxInt32) + 1))); err != nil {
		t.Fatal(err)
	}
	const want = math.MaxInt32
	if e != want {
		t.Errorf("expiration time = %v; want %v", e, want)
	}
}
