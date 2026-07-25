package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

const runP0ArchitectureFailureTests = false

func skipUntilP0ArchitectureFixed(t *testing.T, finding string) {
	t.Helper()
	if !runP0ArchitectureFailureTests {
		t.Skip("P0 characterization disabled until fixed: " + finding)
	}
}

func TestP0FinalGetPatchRaceRejectsConcurrentEdit(t *testing.T) {
	skipUntilP0ArchitectureFixed(t, "no atomic CAS on full-list PATCH — docs/ARCHITECTURE_REVIEW.md §3, Optimistic concurrency")

	t.Run("main planned sync", func(t *testing.T) {
		fake := newP0RaceForwardServer(t, 2, []map[string]any{
			{
				"Cloud Setup ID":     "setup-a",
				"Cloud Account ID":   "111111111111",
				"Cloud Account Name": "existing",
				"Collected?":         true,
			},
			{
				"Cloud Setup ID":     "setup-a",
				"Cloud Account ID":   "222222222222",
				"Cloud Account Name": "planned-addition",
				"Collected?":         true,
			},
		})
		defer fake.server.Close()

		_, err := Run(context.Background(), Config{
			Host:      fake.server.URL,
			Username:  "alice",
			Password:  "secret",
			NetworkID: "network-1",
			QueryID:   "query-1",
			Output:    filepath.Join(t.TempDir(), "payload.json"),
			APIPrefix: "/api",
			Apply:     true,
		})
		assertP0ConcurrentEditRejected(t, "Run()", err, fake)
	})

	t.Run("apply-plan", func(t *testing.T) {
		fake := newP0RaceForwardServer(t, 2, nil)
		defer fake.server.Close()

		planPath := filepath.Join(t.TempDir(), "payload.json")
		writeP0Plan(t, planPath, map[string]api.PatchPayload{
			"setup-a": {
				Type: "AWS",
				Name: "setup-a",
				AssumeRoleInfos: []api.AssumeRoleInfo{
					p0AssumeRole("111111111111", "existing", true),
					p0AssumeRole("222222222222", "planned-addition", true),
				},
			},
		})
		_, err := ApplyPlan(context.Background(), ApplyPlanConfig{
			Host:      fake.server.URL,
			Username:  "alice",
			Password:  "secret",
			NetworkID: "network-1",
			PlanPath:  planPath,
			APIPrefix: "/api",
		})
		assertP0ConcurrentEditRejected(t, "ApplyPlan()", err, fake)
	})

	t.Run("external ID", func(t *testing.T) {
		fake := newP0RaceForwardServer(t, 2, nil)
		defer fake.server.Close()

		_, err := ChangeExternalID(context.Background(), ExternalIDConfig{
			Host:       fake.server.URL,
			Username:   "alice",
			Password:   "secret",
			NetworkID:  "network-1",
			SetupID:    "setup-a",
			ExternalID: "rotated-value",
			Output:     filepath.Join(t.TempDir(), "payload.json"),
			APIPrefix:  "/api",
			Apply:      true,
		})
		assertP0ConcurrentEditRejected(t, "ChangeExternalID()", err, fake)
	})
}

func TestP0IncompleteNonemptyNQEInventoryRequiresCompletenessProof(t *testing.T) {
	skipUntilP0ArchitectureFixed(t, "partial nonempty NQE inventory can become destructive intent — docs/ARCHITECTURE_REVIEW.md §2, Empty and truncated inventory")

	tests := []struct {
		name        string
		repeatPage  bool
		wantOffsets []int
	}{
		{
			name:        "exact multiple of PageLimit",
			wantOffsets: []int{0, api.PageLimit},
		},
		{
			name:        "repeated page does not advance result window",
			repeatPage:  true,
			wantOffsets: []int{0, api.PageLimit},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				mu           sync.Mutex
				patchCount   int
				queryOffsets []int
			)
			current := api.CloudAccount{
				Type: "AWS",
				Name: "setup-a",
				AssumeRoleInfos: []api.AssumeRoleInfo{
					p0AssumeRole("111111111111", "account-1", true),
					p0AssumeRole("222222222222", "account-2", true),
					p0AssumeRole("333333333333", "account-3", true),
					p0AssumeRole("444444444444", "account-4", true),
					p0AssumeRole("555555555555", "account-5", true),
				},
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
					var request api.QueryRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Errorf("decode NQE request: %v", err)
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					mu.Lock()
					queryOffsets = append(queryOffsets, request.QueryOptions.Offset)
					mu.Unlock()
					count := api.PageLimit
					if request.QueryOptions.Offset == api.PageLimit && !test.repeatPage {
						count = 0
					}
					items := make([]map[string]any, count)
					for i := range items {
						accountID := fmt.Sprintf("%012d", i+1)
						items[i] = map[string]any{
							"Cloud Setup ID":     "setup-a",
							"Cloud Account ID":   accountID,
							"Cloud Account Name": "visible-account-" + accountID,
							"Collected?":         true,
						}
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(api.NQEResponse{Items: items})
				case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode([]api.CloudAccount{current})
				case r.Method == http.MethodPatch && r.URL.Path == "/api/networks/network-1/cloudAccounts/setup-a":
					mu.Lock()
					patchCount++
					mu.Unlock()
					w.WriteHeader(http.StatusNoContent)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			_, err := Run(context.Background(), Config{
				Host:               server.URL,
				Username:           "alice",
				Password:           "secret",
				NetworkID:          "network-1",
				QueryID:            "query-1",
				Output:             filepath.Join(t.TempDir(), "payload.json"),
				APIPrefix:          "/api",
				Apply:              true,
				PruneMissing:       true,
				AllowRemovals:      true,
				MaxRemovals:        10,
				MaxRemovalPercent:  100,
				AllowNoCandidates:  true,
				AllowNoOrgEvidence: true,
			})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "complete") {
				t.Errorf("Run() error = %v; want inventory completeness error before destructive planning (removal ceilings deliberately allow 4 removals)", err)
			}
			if err != nil && strings.Contains(strings.ToLower(err.Error()), "blast-radius") {
				t.Errorf("Run() failed on removal ceilings instead of inventory completeness: %v", err)
			}
			mu.Lock()
			gotPatchCount := patchCount
			gotOffsets := append([]int(nil), queryOffsets...)
			mu.Unlock()
			if gotPatchCount != 0 {
				t.Errorf("PATCH count = %d; want 0 when inventory completeness is unproven", gotPatchCount)
			}
			if fmt.Sprint(gotOffsets) != fmt.Sprint(test.wantOffsets) {
				t.Errorf("NQE offsets = %v; want %v", gotOffsets, test.wantOffsets)
			}
		})
	}
}

func TestP0ShortFirstPageTruncationCannotBeDetectedClientSide(t *testing.T) {
	t.Skip("a server can return a plausible short first page that omits real AWS accounts; the client has no independent expected count, so unattended absence-based pruning is prohibited by operating policy rather than detected in code")
}

func TestP0PartialMultiSetupApplyReturnsDispositionAndResumesSafely(t *testing.T) {
	skipUntilP0ArchitectureFixed(t, "multi-setup PATCH has no durable partial result or safe resume — docs/ARCHITECTURE_REVIEW.md §3, Idempotency, retries, and partial failure")

	var (
		mu            sync.Mutex
		patchAttempts = map[string]int{}
		state         = map[string]api.CloudAccount{
			"setup-a": {
				Type:            "AWS",
				Name:            "setup-a",
				AssumeRoleInfos: []api.AssumeRoleInfo{p0AssumeRole("111111111111", "a-existing", true)},
			},
			"setup-b": {
				Type:            "AWS",
				Name:            "setup-b",
				AssumeRoleInfos: []api.AssumeRoleInfo{p0AssumeRole("333333333333", "b-existing", true)},
			},
		}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			_ = json.NewEncoder(w).Encode(api.NQEResponse{Items: []map[string]any{
				{"Cloud Setup ID": "setup-a", "Cloud Account ID": "111111111111", "Cloud Account Name": "a-existing", "Collected?": true},
				{"Cloud Setup ID": "setup-a", "Cloud Account ID": "222222222222", "Cloud Account Name": "a-addition", "Collected?": true},
				{"Cloud Setup ID": "setup-b", "Cloud Account ID": "333333333333", "Cloud Account Name": "b-existing", "Collected?": true},
				{"Cloud Setup ID": "setup-b", "Cloud Account ID": "444444444444", "Cloud Account Name": "b-addition", "Collected?": true},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			mu.Lock()
			accounts := []api.CloudAccount{
				cloneP0CloudAccount(state["setup-a"]),
				cloneP0CloudAccount(state["setup-b"]),
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(accounts)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/networks/network-1/cloudAccounts/"):
			setupID := strings.TrimPrefix(r.URL.Path, "/api/networks/network-1/cloudAccounts/")
			var payload api.PatchPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode PATCH: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			patchAttempts[setupID]++
			attempt := patchAttempts[setupID]
			if setupID == "setup-b" && attempt == 1 {
				mu.Unlock()
				http.Error(w, "injected setup-b failure", http.StatusInternalServerError)
				return
			}
			account := state[setupID]
			account.AssumeRoleInfos = append([]api.AssumeRoleInfo(nil), payload.AssumeRoleInfos...)
			state[setupID] = account
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	base := Config{
		Host:      server.URL,
		Username:  "alice",
		Password:  "secret",
		NetworkID: "network-1",
		QueryID:   "query-1",
		APIPrefix: "/api",
		Apply:     true,
	}
	firstConfig := base
	firstConfig.Output = filepath.Join(t.TempDir(), "first.json")
	first, firstErr := Run(context.Background(), firstConfig)
	if firstErr == nil || !strings.Contains(firstErr.Error(), "setup-b") {
		t.Errorf("first Run() error = %v; want injected setup-b failure", firstErr)
	}
	if first == nil {
		t.Errorf("first Run() summary = nil; want applied=[setup-a] pending=[setup-b]")
	} else {
		applied, pending := p0SetupDisposition(first)
		if fmt.Sprint(applied) != "[setup-a]" || fmt.Sprint(pending) != "[setup-b]" {
			t.Errorf("first Run() disposition applied=%v pending=%v; want applied=[setup-a] pending=[setup-b]", applied, pending)
		}
	}

	secondConfig := base
	secondConfig.Output = filepath.Join(t.TempDir(), "second.json")
	second, secondErr := Run(context.Background(), secondConfig)
	if secondErr != nil {
		t.Fatalf("second Run() error = %v; want safe resume", secondErr)
	}
	mu.Lock()
	attemptsA := patchAttempts["setup-a"]
	attemptsB := patchAttempts["setup-b"]
	mu.Unlock()
	if attemptsA != 1 {
		t.Errorf("setup-a PATCH attempts = %d; want 1 so rerun does not rewrite an already-applied setup", attemptsA)
	}
	if attemptsB != 2 {
		t.Errorf("setup-b PATCH attempts = %d; want 2 (failed attempt plus resumed success)", attemptsB)
	}
	secondPatchedCount := -1
	if second != nil {
		secondPatchedCount = second.PatchedSetupCount
	}
	if secondPatchedCount != 1 {
		t.Errorf("second Run() patched_setup_count = %d; want 1 for the pending setup only", secondPatchedCount)
	}
}

func TestP0ApplyPlanDisableRequiresDestructiveAuthorization(t *testing.T) {
	skipUntilP0ArchitectureFixed(t, "same-membership enabled=false bypasses destructive guards — docs/ARCHITECTURE_REVIEW.md §2, All intentional and incidental removal/disable paths")

	tests := []struct {
		name              string
		allowRemovals     bool
		maxRemovals       int
		maxRemovalPercent float64
		allowUnattended   bool
		wantError         string
	}{
		{
			name:      "no destructive authorization",
			wantError: "--allow-removals",
		},
		{
			name:          "authorization without bounds",
			allowRemovals: true,
			wantError:     "require both",
		},
		{
			name:              "authorization and bounds",
			allowRemovals:     true,
			maxRemovals:       2,
			maxRemovalPercent: 100,
			allowUnattended:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var patchCount int
			current := api.CloudAccount{
				Type: "AWS",
				Name: "setup-a",
				AssumeRoleInfos: []api.AssumeRoleInfo{
					p0AssumeRole("111111111111", "account-1", true),
					p0AssumeRole("222222222222", "account-2", true),
				},
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
					_ = json.NewEncoder(w).Encode([]api.CloudAccount{current})
				case r.Method == http.MethodPatch && r.URL.Path == "/api/networks/network-1/cloudAccounts/setup-a":
					patchCount++
					w.WriteHeader(http.StatusNoContent)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			planPath := filepath.Join(t.TempDir(), "disable.json")
			writeP0Plan(t, planPath, map[string]api.PatchPayload{
				"setup-a": {
					Type: "AWS",
					Name: "setup-a",
					AssumeRoleInfos: []api.AssumeRoleInfo{
						p0AssumeRole("111111111111", "account-1", false),
						p0AssumeRole("222222222222", "account-2", false),
					},
				},
			})
			_, err := ApplyPlan(context.Background(), ApplyPlanConfig{
				Host:                       server.URL,
				Username:                   "alice",
				Password:                   "secret",
				NetworkID:                  "network-1",
				PlanPath:                   planPath,
				APIPrefix:                  "/api",
				AllowRemovals:              test.allowRemovals,
				MaxRemovals:                test.maxRemovals,
				MaxRemovalPercent:          test.maxRemovalPercent,
				AllowUnattendedDestructive: test.allowUnattended,
			})
			if test.wantError == "" {
				if err != nil {
					t.Errorf("ApplyPlan() error = %v; want authorized disable to proceed", err)
				}
				if patchCount != 1 {
					t.Errorf("PATCH count = %d; want 1 for authorized disable", patchCount)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Errorf("ApplyPlan() error = %v; want destructive authorization error containing %q", err, test.wantError)
			}
			if patchCount != 0 {
				t.Errorf("PATCH count = %d; want 0 without complete destructive authorization", patchCount)
			}
		})
	}
}

type p0RaceForwardServer struct {
	server *httptest.Server

	mu               sync.Mutex
	setup            api.CloudAccount
	version          string
	getCount         int
	mutateAfterGet   int
	patchCount       int
	concurrentID     string
	nqeItems         []map[string]any
	handlerAssertion error
}

func newP0RaceForwardServer(t *testing.T, mutateAfterGet int, nqeItems []map[string]any) *p0RaceForwardServer {
	t.Helper()
	fake := &p0RaceForwardServer{
		setup: api.CloudAccount{
			Type:            "AWS",
			Name:            "setup-a",
			AssumeRoleInfos: []api.AssumeRoleInfo{p0AssumeRole("111111111111", "existing", true)},
		},
		version:        `"version-1"`,
		mutateAfterGet: mutateAfterGet,
		concurrentID:   "999999999999",
		nqeItems:       nqeItems,
	}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(api.NQEResponse{Items: fake.nqeItems})
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			fake.mu.Lock()
			fake.getCount++
			getCount := fake.getCount
			snapshot := cloneP0CloudAccount(fake.setup)
			version := fake.version
			fake.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", version)
			_ = json.NewEncoder(w).Encode([]api.CloudAccount{snapshot})

			if getCount == fake.mutateAfterGet {
				fake.mu.Lock()
				fake.setup.AssumeRoleInfos = append(fake.setup.AssumeRoleInfos, p0AssumeRole(fake.concurrentID, "concurrent-ui-addition", true))
				fake.version = `"version-2"`
				fake.mu.Unlock()
			}
		case r.Method == http.MethodPatch && r.URL.Path == "/api/networks/network-1/cloudAccounts/setup-a":
			var payload struct {
				AssumeRoleInfos []api.AssumeRoleInfo `json:"assumeRoleInfos"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				fake.mu.Lock()
				fake.handlerAssertion = fmt.Errorf("decode PATCH: %w", err)
				fake.mu.Unlock()
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			fake.mu.Lock()
			ifMatch := r.Header.Get("If-Match")
			if ifMatch != "" && ifMatch != fake.version {
				fake.mu.Unlock()
				http.Error(w, "revision conflict", http.StatusPreconditionFailed)
				return
			}
			fake.setup.AssumeRoleInfos = append([]api.AssumeRoleInfo(nil), payload.AssumeRoleInfos...)
			fake.patchCount++
			fake.version = `"version-3"`
			fake.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	return fake
}

func assertP0ConcurrentEditRejected(t *testing.T, operation string, err error, fake *p0RaceForwardServer) {
	t.Helper()
	lowerError := strings.ToLower(fmt.Sprint(err))
	conflict := err != nil && (strings.Contains(lowerError, "conflict") ||
		strings.Contains(lowerError, "precondition") ||
		strings.Contains(lowerError, "status 412") ||
		strings.Contains(lowerError, "changed after planning"))
	if !conflict {
		t.Errorf("%s error = %v; want atomic conflict after concurrent Forward edit", operation, err)
	}
	fake.mu.Lock()
	patchCount := fake.patchCount
	handlerAssertion := fake.handlerAssertion
	hasConcurrent := false
	for _, info := range fake.setup.AssumeRoleInfos {
		if info.AccountID == fake.concurrentID {
			hasConcurrent = true
			break
		}
	}
	fake.mu.Unlock()
	if handlerAssertion != nil {
		t.Errorf("fake Forward server assertion: %v", handlerAssertion)
	}
	if patchCount != 0 {
		t.Errorf("%s committed PATCH count = %d; want 0 after concurrent edit", operation, patchCount)
	}
	if !hasConcurrent {
		t.Errorf("%s clobbered concurrent account %s; want concurrent edit preserved", operation, fake.concurrentID)
	}
}

func p0AssumeRole(accountID, accountName string, enabled bool) api.AssumeRoleInfo {
	return api.AssumeRoleInfo{
		AccountID:   accountID,
		AccountName: accountName,
		RoleArn:     "arn:aws:iam::" + accountID + ":role/ForwardRole",
		Enabled:     enabled,
	}
}

func cloneP0CloudAccount(account api.CloudAccount) api.CloudAccount {
	account.AssumeRoleInfos = append([]api.AssumeRoleInfo(nil), account.AssumeRoleInfos...)
	if account.Regions != nil {
		regions := account.Regions
		account.Regions = make(map[string]api.RegionMeta, len(account.Regions))
		for region, metadata := range regions {
			account.Regions[region] = metadata
		}
	}
	if account.RegionToProxyServerID != nil {
		regionToProxy := account.RegionToProxyServerID
		account.RegionToProxyServerID = make(map[string]string, len(account.RegionToProxyServerID))
		for region, proxy := range regionToProxy {
			account.RegionToProxyServerID[region] = proxy
		}
	}
	return account
}

func writeP0Plan(t *testing.T, path string, payloads map[string]api.PatchPayload) {
	t.Helper()
	data, err := json.Marshal(payloads)
	if err != nil {
		t.Fatalf("encode plan: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write plan: %v", err)
	}
}

func p0SetupDisposition(summary *Summary) (applied, pending []string) {
	for _, setup := range summary.PlannedSetups {
		if setup.Patched {
			applied = append(applied, setup.SetupID)
		} else {
			pending = append(pending, setup.SetupID)
		}
	}
	sort.Strings(applied)
	sort.Strings(pending)
	return applied, pending
}
