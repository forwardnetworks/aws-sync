package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const runP0APIFailureTests = false

func skipUntilP0APIFixed(t *testing.T, finding string) {
	t.Helper()
	if !runP0APIFailureTests {
		t.Skip("P0 characterization disabled until fixed: " + finding)
	}
}

func TestP0AmbiguousPATCHRetryPreservesInterleavedEdit(t *testing.T) {
	skipUntilP0APIFixed(t, "retryable PATCH has no idempotency key or revision precondition — docs/ARCHITECTURE_REVIEW.md §3, Idempotency, retries, and partial failure")

	const concurrentAccountID = "999999999999"
	var (
		mu              sync.Mutex
		attempts        int
		applyCount      int
		version         = `"version-1"`
		stored          []AssumeRoleInfo
		idempotencyKeys []string
		ifMatches       []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/networks/network-1/cloudAccounts/setup-a" {
			http.NotFound(w, r)
			return
		}
		var payload PatchPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		mu.Lock()
		attempts++
		attempt := attempts
		key := r.Header.Get("Idempotency-Key")
		ifMatch := r.Header.Get("If-Match")
		idempotencyKeys = append(idempotencyKeys, key)
		ifMatches = append(ifMatches, ifMatch)

		if attempt > 1 && key != "" && key == idempotencyKeys[0] {
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if ifMatch != "" && ifMatch != version {
			mu.Unlock()
			http.Error(w, "revision conflict", http.StatusPreconditionFailed)
			return
		}

		stored = append([]AssumeRoleInfo(nil), payload.AssumeRoleInfos...)
		applyCount++
		if attempt == 1 {
			stored = append(stored, AssumeRoleInfo{
				AccountID:   concurrentAccountID,
				AccountName: "interleaved-ui-edit",
				RoleArn:     "arn:aws:iam::" + concurrentAccountID + ":role/ForwardRole",
				Enabled:     true,
			})
			version = `"version-2"`
			mu.Unlock()

			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Errorf("ResponseWriter does not implement http.Hijacker")
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("hijack committed response: %v", err)
				return
			}
			_ = connection.Close()
			return
		}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "/api", "alice", "secret", false, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	client.retryDelay = time.Millisecond
	err = client.PatchCloudAccount(context.Background(), "network-1", "setup-a", PatchPayload{
		Type: "AWS",
		Name: "setup-a",
		AssumeRoleInfos: []AssumeRoleInfo{{
			AccountID:   "111111111111",
			AccountName: "planned-account",
			RoleArn:     "arn:aws:iam::111111111111:role/ForwardRole",
			Enabled:     true,
		}},
	})

	mu.Lock()
	gotAttempts := attempts
	gotApplyCount := applyCount
	gotStored := append([]AssumeRoleInfo(nil), stored...)
	gotKeys := append([]string(nil), idempotencyKeys...)
	gotMatches := append([]string(nil), ifMatches...)
	mu.Unlock()

	hasStableIdempotencyKey := len(gotKeys) >= 2 && gotKeys[0] != "" && gotKeys[0] == gotKeys[1]
	hasStableRevision := len(gotMatches) >= 2 && gotMatches[0] != "" && gotMatches[0] == gotMatches[1]
	if !hasStableIdempotencyKey && !hasStableRevision {
		t.Errorf("PATCH retry headers idempotency=%q if-match=%q; want a stable idempotency key or revision precondition", gotKeys, gotMatches)
	}
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "conflict") &&
		!strings.Contains(strings.ToLower(err.Error()), "precondition") &&
		!strings.Contains(strings.ToLower(err.Error()), "status 412") {
		t.Errorf("PatchCloudAccount() error = %v; want success from idempotent replay or an explicit revision conflict", err)
	}
	if gotAttempts != 2 {
		t.Errorf("PATCH attempts = %d; want 2 to exercise ambiguous committed-response retry", gotAttempts)
	}
	if gotApplyCount != 1 {
		t.Errorf("server-side apply count = %d; want 1 after ambiguous retry", gotApplyCount)
	}
	hasConcurrentAccount := false
	for _, info := range gotStored {
		if info.AccountID == concurrentAccountID {
			hasConcurrentAccount = true
			break
		}
	}
	if !hasConcurrentAccount {
		t.Errorf("retry overwrote interleaved account %s; want concurrent edit preserved", concurrentAccountID)
	}
}
