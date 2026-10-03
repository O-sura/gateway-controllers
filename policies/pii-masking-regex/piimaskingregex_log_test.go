package piimaskingregex

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// captureDebugLogs routes the default slog logger to a buffer at debug level
// for the duration of the test.
func captureDebugLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestPIIDetectionDebugLog_NeverContainsValues(t *testing.T) {
	const email = "a.user@example.com"
	tests := []struct {
		name   string
		params map[string]interface{}
		action string
	}{
		{"mask", map[string]interface{}{"email": true}, "action=mask"},
		{"redact", map[string]interface{}{"email": true, "redactPII": true}, "action=redact"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureDebugLogs(t)
			p := mustGetPIIPolicy(t, tc.params)

			ctx := piiRequestContext(`{"messages":[{"content":"mail ` + email + ` or ` + email + `"}]}`)
			p.OnRequestBody(context.Background(), ctx, nil)

			out := buf.String()
			for _, want := range []string{`msg="PIIMaskingRegex: PII detected"`, tc.action, "entities=map[EMAIL:2]", "matchCount=2", "jsonPath="} {
				if !strings.Contains(out, want) {
					t.Errorf("expected log to contain %q, got:\n%s", want, out)
				}
			}
			if strings.Contains(out, email) || strings.Contains(out, "example.com") {
				t.Fatalf("debug log leaked PII value:\n%s", out)
			}
		})
	}
}

func TestPIIDetectionDebugLog_NoMatch(t *testing.T) {
	buf := captureDebugLogs(t)
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})

	p.OnRequestBody(context.Background(), piiRequestContext(`{"messages":[{"content":"no pii here"}]}`), nil)

	if out := buf.String(); !strings.Contains(out, `msg="PIIMaskingRegex: no PII detected"`) {
		t.Fatalf("expected no-PII debug log, got:\n%s", out)
	}
}
