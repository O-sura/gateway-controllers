package regexguardrail

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
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

func assertLogContains(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("expected log to contain %q, got:\n%s", want, out)
		}
	}
}

func TestRegexGuardrailDebugLog_Request(t *testing.T) {
	const secret = "sk-abc123secret"
	tests := []struct {
		name   string
		invert bool
		want   []string
	}{
		{"allowlist passes", false, []string{`msg="RegexGuardrail: Validation passed"`, "matched=true", "matchCount=2", "invert=false"}},
		{"blocklist fails", true, []string{`msg="RegexGuardrail: Validation failed"`, "matched=true", "matchCount=2", "invert=true"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureDebugLogs(t)
			p := mustGetRegexPolicy(t, map[string]interface{}{
				"request": map[string]interface{}{"regex": `sk-[a-z0-9]+`, "invert": tc.invert},
			})

			p.OnRequestBody(context.Background(), newRequestContextWithBody(`{"messages":[{"content":"keys `+secret+` and sk-def456"}]}`), nil)

			out := buf.String()
			assertLogContains(t, out, append(tc.want, "jsonPath=$.messages[-1].content", "isResponse=false")...)
			if strings.Contains(out, secret) {
				t.Fatalf("debug log leaked matched content:\n%s", out)
			}
		})
	}
}

func TestRegexGuardrailDebugLog_NoMatch(t *testing.T) {
	buf := captureDebugLogs(t)
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{"regex": `sk-[a-z0-9]+`, "invert": true},
	})

	p.OnRequestBody(context.Background(), newRequestContextWithBody(`{"messages":[{"content":"nothing here"}]}`), nil)

	assertLogContains(t, buf.String(), `msg="RegexGuardrail: Validation passed"`, "matched=false", "matchCount=0")
}

func TestRegexGuardrailDebugLog_Streaming(t *testing.T) {
	sse := func(content string) []byte {
		return []byte(`data: {"choices":[{"delta":{"content":"` + content + `"}}]}` + "\n\n")
	}
	tests := []struct {
		name   string
		invert bool
		chunks [][]byte
		want   string
	}{
		{"blocklist violation", true, [][]byte{sse("token sk-abc"), sse("123secret")}, `msg="RegexGuardrail: streaming validation failed"`},
		{"allowlist passes at end", false, [][]byte{sse("token sk-abc"), sse("123secret")}, `msg="RegexGuardrail: streaming validation passed"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureDebugLogs(t)
			p := mustGetRegexPolicy(t, map[string]interface{}{
				"response": map[string]interface{}{"enabled": true, "regex": `sk-[a-z0-9]+`, "invert": tc.invert, "streamingJsonPath": DefaultStreamingJsonPath},
			})
			respCtx := &policy.ResponseStreamContext{SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}}}
			for i, c := range tc.chunks {
				p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{Chunk: c, Index: uint64(i), EndOfStream: i == len(tc.chunks)-1}, nil)
			}

			out := buf.String()
			assertLogContains(t, out, tc.want, "jsonPath=$.choices[0].delta.content", "matched=true", "matchCount=1")
			if strings.Contains(out, "sk-abc") {
				t.Fatalf("debug log leaked matched content:\n%s", out)
			}
		})
	}
}
