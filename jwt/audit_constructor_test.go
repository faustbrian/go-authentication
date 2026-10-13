package jwt

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestFailedRemoteConstructorJoinsCanceledWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		defer releaseOnce.Do(func() { close(release) })
		client := &http.Client{Transport: internalRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			close(started)
			<-request.Context().Done()
			close(canceled)
			<-release
			return nil, errors.New("private transport diagnostic")
		})}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			remote, err := NewRemote(ctx, "https://issuer.example.test/keys?private-query", WithHTTPClient(client), WithInitializationTimeout(time.Second))
			if remote != nil {
				_ = remote.Shutdown(context.Background())
			}
			done <- err
		}()
		<-started
		cancel()
		<-canceled
		synctest.Wait()
		select {
		case err := <-done:
			t.Errorf("constructor returned before canceled worker finished: %v", err)
		default:
		}
		releaseOnce.Do(func() { close(release) })
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "private") {
				t.Errorf("constructor cancellation classification/privacy = %v", err)
			}
		default:
			t.Error("constructor did not finish after worker release")
		}
	})
}

func TestFailedRemoteConstructorReportsBoundedCleanupFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		defer close(release)
		client := &http.Client{Transport: internalRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			close(started)
			<-request.Context().Done()
			<-release
			return nil, request.Context().Err()
		})}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := NewRemote(ctx, "https://issuer.example.test/keys", WithHTTPClient(client), WithInitializationTimeout(time.Second))
			done <- err
		}()
		<-started
		cancel()
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) || !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("constructor error = %v; want initial cancellation and cleanup deadline", err)
			}
		default:
			t.Error("constructor cleanup exceeded its existing initialization budget")
		}
	})
}
