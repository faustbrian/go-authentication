package authotel_test

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authentication/adapters/otel/v2"
	authentication "github.com/faustbrian/go-authentication/v3"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

func ExampleNew() {
	instrumenter, err := authotel.New(authotel.Config{
		TracerProvider: tracenoop.NewTracerProvider(),
		MeterProvider:  metricnoop.NewMeterProvider(),
	})
	if err != nil {
		fmt.Println("configuration error")
		return
	}
	_, finish := instrumenter.Begin(context.Background(), authentication.CredentialBearer)
	finish(authentication.Event{Outcome: authentication.OutcomeAuthenticated})
	fmt.Println("instrumented")
	// Output: instrumented
}
