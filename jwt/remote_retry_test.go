package jwt_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authentication/authtest"
	authjwt "github.com/faustbrian/go-authentication/jwt"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

func TestRemoteAutomaticFailureCadenceAndRecovery(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		mode     string
		minimum  time.Duration
		interval time.Duration
	}{
		{"default transport", "transport", 0, time.Minute},
		{"default malformed success", "malformed", 0, time.Minute},
		{"status follows cache header", "status", 0, 90 * time.Second},
		{"configured transport", "transport", 10 * time.Second, 10 * time.Second},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fixture := newRemoteRetryFixture(t, scenario.minimum)
				defer fixture.shutdown(t)
				fixture.transport.set(scenario.mode, nil)
				fixture.awaitRequest(t, 2, time.Minute+2*time.Second)
				for range 2 {
					failedAt := fixture.transport.lastRequest()
					before := fixture.transport.count()
					fixture.assertTrust(t, fixture.firstToken, fixture.secondToken)
					time.Sleep(time.Until(failedAt.Add(scenario.interval - time.Nanosecond)))
					synctest.Wait()
					if got := fixture.transport.count(); got != before {
						t.Fatalf("automatic retry before minimum/header deadline: requests = %d, want %d", got, before)
					}
					fixture.awaitRequest(t, before+1, 3*time.Second)
					if elapsed := fixture.transport.lastRequest().Sub(failedAt); elapsed < scenario.interval {
						t.Fatalf("retry interval = %v, want at least %v", elapsed, scenario.interval)
					}
				}
				fixture.transport.set("success", fixture.secondBody)
				fixture.awaitRequest(t, fixture.transport.count()+1, scenario.interval+2*time.Second)
				fixture.assertTrust(t, fixture.secondToken, fixture.firstToken)
			})
		})
	}
}

func TestRemoteExplicitRefreshBypassesAutomaticFailureBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture := newRemoteRetryFixture(t, 0)
		defer fixture.shutdown(t)
		fixture.transport.set("transport", nil)
		fixture.awaitRequest(t, 2, time.Minute+2*time.Second)
		before, now := fixture.transport.count(), time.Now()
		if err := fixture.remote.Refresh(context.Background()); !errors.Is(err, authentication.ErrAuthenticationUnavailable) {
			t.Fatalf("explicit failed Refresh = %v", err)
		}
		if fixture.transport.count() != before+1 || !time.Now().Equal(now) {
			t.Fatal("explicit failure waited for automatic backoff")
		}
		fixture.assertTrust(t, fixture.firstToken, fixture.secondToken)
		fixture.transport.set("success", fixture.secondBody)
		if err := fixture.remote.Refresh(context.Background()); err != nil {
			t.Fatalf("explicit recovery = %v", err)
		}
		if fixture.transport.count() != before+2 || !time.Now().Equal(now) {
			t.Fatal("explicit recovery waited for automatic backoff")
		}
		fixture.assertTrust(t, fixture.secondToken, fixture.firstToken)
	})
}

func TestRemoteShutdownStopsPendingAutomaticRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture := newRemoteRetryFixture(t, 0)
		defer fixture.shutdown(t)
		fixture.transport.set("transport", nil)
		fixture.awaitRequest(t, 2, time.Minute+2*time.Second)
		fixture.shutdown(t)
		before := fixture.transport.count()
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if fixture.transport.count() != before {
			t.Fatal("shutdown left automatic retry work running")
		}
		if _, err := fixture.remote.KeySet(context.Background()); !errors.Is(err, authentication.ErrAuthenticationUnavailable) {
			t.Fatalf("KeySet after shutdown = %v", err)
		}
		if err := fixture.remote.Refresh(context.Background()); !errors.Is(err, authentication.ErrAuthenticationUnavailable) {
			t.Fatalf("Refresh after shutdown = %v", err)
		}
		if fixture.transport.count() != before {
			t.Fatal("closed operations admitted a request")
		}
	})
}

func TestRemoteShutdownCancelsAutomaticWorkNotRefreshWaiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture := newRemoteRetryFixture(t, 0)
		defer fixture.shutdown(t)
		fixture.transport.set("block", nil)
		fixture.awaitRequest(t, 2, time.Minute+2*time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- fixture.remote.Refresh(ctx) }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, authentication.ErrAuthenticationUnavailable) || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter = %v", err)
		}
		if fixture.transport.activeCount() != 1 || fixture.transport.count() != 2 {
			t.Fatal("waiter canceled or overlapped the automatic request")
		}
		fixture.shutdown(t)
		if fixture.transport.activeCount() != 0 || fixture.transport.canceledCount() != 1 {
			t.Fatal("shutdown did not cancel and join automatic transport work")
		}
		before := fixture.transport.count()
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if fixture.transport.count() != before {
			t.Fatal("shutdown admitted further automatic work")
		}
	})
}

type remoteRetryFixture struct {
	remote                  *authjwt.Remote
	validator               *authjwt.Validator
	transport               *retryTransport
	firstToken, secondToken string
	secondBody              []byte
}

func newRemoteRetryFixture(t *testing.T, minimum time.Duration) remoteRetryFixture {
	t.Helper()
	firstSet, firstSigner := rsaKeys(t, "retry-first", jwa.RS256())
	secondSet, secondSigner := rsaKeys(t, "retry-second", jwa.RS256())
	transport := &retryTransport{mode: "success", body: marshalJWKSet(t, firstSet)}
	options := []authjwt.RemoteOption{
		authjwt.WithHTTPClient(&http.Client{Transport: transport}),
		authjwt.WithRefreshJitter(0),
	}
	if minimum != 0 {
		options = append(options, authjwt.WithRefreshBounds(minimum, time.Hour))
	}
	remote, err := authjwt.NewRemote(context.Background(), "https://retry.example.test/keys", options...)
	if err != nil {
		t.Fatalf("NewRemote = %v", err)
	}
	validator, err := authjwt.New(authjwt.Config{
		Issuer: "https://issuer.example.test", Audience: "orders",
		Algorithms: []jwa.SignatureAlgorithm{jwa.RS256()}, Provider: remote,
		Clock: authtest.NewClock(jwtNow),
	})
	if err != nil {
		_ = remote.Shutdown(context.Background())
		t.Fatalf("New validator = %v", err)
	}
	claims := map[string]any{"sub": "retry-service", "iss": "https://issuer.example.test", "aud": "orders", "iat": jwtNow, "exp": jwtNow.Add(time.Hour)}
	fixture := remoteRetryFixture{remote, validator, transport,
		signedToken(t, firstSigner, jwa.RS256(), claims), signedToken(t, secondSigner, jwa.RS256(), claims), marshalJWKSet(t, secondSet)}
	synctest.Wait()
	if transport.count() != 1 {
		t.Fatalf("initial requests = %d, want 1", transport.count())
	}
	fixture.assertTrust(t, fixture.firstToken, fixture.secondToken)
	return fixture
}

func (f remoteRetryFixture) assertTrust(t *testing.T, accepted, rejected string) {
	t.Helper()
	before := f.transport.count()
	result, err := f.validator.Authenticate(context.Background(), authentication.NewBearerCredential(accepted))
	principal, ok := result.Principal()
	if err != nil || !ok || principal.Subject() != "retry-service" || principal.Issuer() != "https://issuer.example.test" {
		t.Fatalf("cached known-key authentication = %v, subject/issuer = %q/%q", err, principal.Subject(), principal.Issuer())
	}
	if _, err := f.validator.Authenticate(context.Background(), authentication.NewBearerCredential(rejected)); !errors.Is(err, authentication.ErrCredentialsRejected) {
		t.Fatalf("unknown/evicted key authentication = %v", err)
	}
	if f.transport.count() != before {
		t.Fatal("validation triggered remote work")
	}
}

func (f remoteRetryFixture) awaitRequest(t *testing.T, want int, maximum time.Duration) {
	t.Helper()
	deadline := time.Now().Add(maximum)
	for f.transport.count() < want && time.Now().Before(deadline) {
		time.Sleep(time.Second)
		synctest.Wait()
	}
	if got := f.transport.count(); got != want {
		t.Fatalf("requests = %d, want %d within %v", got, want, maximum)
	}
}

func (f remoteRetryFixture) shutdown(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.remote.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	synctest.Wait()
}

type retryTransport struct {
	mutex    sync.Mutex
	mode     string
	body     []byte
	requests []time.Time
	active   int
	canceled int
}

func (r *retryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.mutex.Lock()
	r.requests = append(r.requests, time.Now())
	mode, body := r.mode, r.body
	if mode == "block" {
		r.active++
	}
	r.mutex.Unlock()
	if mode == "block" {
		<-request.Context().Done()
		r.mutex.Lock()
		r.active--
		r.canceled++
		r.mutex.Unlock()
		return nil, request.Context().Err()
	}
	if mode == "transport" {
		return nil, errors.New("simulated key endpoint outage")
	}
	status := http.StatusOK
	header := make(http.Header)
	if mode == "malformed" {
		body = []byte(`{"keys":[`)
		header.Set("Cache-Control", "max-age=90")
	}
	if mode == "status" {
		status = http.StatusServiceUnavailable
		header.Set("Cache-Control", "max-age=90")
	}
	return &http.Response{StatusCode: status, Header: header,
		Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
}

func (r *retryTransport) set(mode string, body []byte) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.mode, r.body = mode, body
}

func (r *retryTransport) count() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return len(r.requests)
}

func (r *retryTransport) lastRequest() time.Time {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.requests[len(r.requests)-1]
}

func (r *retryTransport) activeCount() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.active
}

func (r *retryTransport) canceledCount() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.canceled
}
