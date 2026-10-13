package jwt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestRefreshFollowerKeepsAdmittedGenerationResult(t *testing.T) {
	for _, firstFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "success then failure", true: "failure then success"}[firstFails], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				firstStarted, finishFirst := make(chan struct{}), make(chan struct{})
				var requests atomic.Int32
				client := &http.Client{Transport: internalRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					generation := requests.Add(1)
					if generation == 2 {
						close(firstStarted)
						<-finishFirst
					}
					if generation == 2 && firstFails || generation == 3 && !firstFails {
						return nil, errors.New("selected generation unavailable")
					}
					return &http.Response{StatusCode: http.StatusOK,
						Header: http.Header{"Cache-Control": {"max-age=3600"}},
						Body:   io.NopCloser(bytes.NewBufferString(`{"keys":[{"kty":"oct","kid":"key","alg":"HS256","k":"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE"}]}`)), Request: request}, nil
				})}
				remote, err := NewRemote(context.Background(), "https://issuer.example.test/keys", WithHTTPClient(client), WithRefreshJitter(0), WithRefreshBounds(time.Hour, time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := remote.Shutdown(context.Background()); err != nil {
						t.Error(err)
					}
				}()
				leaderDone := make(chan error, 1)
				go func() { leaderDone <- remote.refresh(context.Background(), remote.cache) }()
				<-firstStarted
				waiting, resume := make(chan struct{}), make(chan struct{})
				followerDone := make(chan error, 1)
				go func() {
					followerDone <- remote.refresh(gatedRefreshContext{Context: context.Background(), waiting: waiting, resume: resume}, remote.cache)
				}()
				<-waiting
				close(finishFirst)
				firstErr := <-leaderDone
				secondErr := remote.refresh(context.Background(), remote.cache)
				if (firstErr != nil) != firstFails || (secondErr != nil) == firstFails {
					close(resume)
					t.Fatalf("generation controls = %v, %v", firstErr, secondErr)
				}
				close(resume)
				if err := <-followerDone; (err != nil) != firstFails {
					t.Errorf("follower result = %v; admitted generation result = %v", err, firstErr)
				}
				if requests.Load() != 3 {
					t.Errorf("requests = %d; want initialization and two generations", requests.Load())
				}
			})
		})
	}
}

// Gate the follower after it captures its in-flight generation but before it
// receives completion, making a later generation finish first deterministically.
type gatedRefreshContext struct {
	context.Context
	waiting chan<- struct{}
	resume  <-chan struct{}
}

func (ctx gatedRefreshContext) Done() <-chan struct{} {
	close(ctx.waiting)
	<-ctx.resume
	return ctx.Context.Done()
}
