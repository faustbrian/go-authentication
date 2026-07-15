package authotel_test

import (
	"context"
	"fmt"

	authentication "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authentication/authotel"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

func ExampleNew() {
	instrumenter, _ := authotel.New(authotel.Config{
		TracerProvider: tracenoop.NewTracerProvider(),
		MeterProvider:  metricnoop.NewMeterProvider(),
	})
	_, finish := instrumenter.Start(context.Background(), authentication.CredentialBearer)
	finish(authentication.Event{Outcome: authentication.OutcomeAuthenticated})
	fmt.Println("instrumented")
	// Output: instrumented
}
