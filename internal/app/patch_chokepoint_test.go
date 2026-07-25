package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatchCloudAccountProductionCallersAreChokepointed(t *testing.T) {
	allowed := map[string]bool{
		filepath.Clean("internal/app/apply_gateway.go"): true,
	}
	counts := make(map[string]int)
	err := filepath.Walk(filepath.Clean("../.."), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		count := strings.Count(string(data), ".PatchCloudAccount(")
		if count == 0 {
			return nil
		}
		relative, err := filepath.Rel("../..", path)
		if err != nil {
			return err
		}
		relative = filepath.Clean(relative)
		if !allowed[relative] {
			t.Errorf("production caller of api.PatchCloudAccount outside gateway: %s", relative)
		}
		counts[relative] += count
		return nil
	})
	if err != nil {
		t.Fatalf("scan production Go sources: %v", err)
	}
	if counts[filepath.Clean("internal/app/apply_gateway.go")] != 1 {
		t.Fatalf("gateway PatchCloudAccount call count = %d, want exactly 1", counts[filepath.Clean("internal/app/apply_gateway.go")])
	}
}
