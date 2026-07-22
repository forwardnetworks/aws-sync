package app

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

type externalIDAssignments map[string]map[string]string

func loadExternalIDAssignments(path, defaultSetupID string) (externalIDAssignments, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open external ID file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read external ID file header: %w", err)
	}
	for i := range header {
		header[i] = strings.ToLower(strings.TrimSpace(header[i]))
	}
	withSetup := equalStrings(header, []string{"setup_id", "account_id", "action", "external_id"})
	withoutSetup := equalStrings(header, []string{"account_id", "action", "external_id"})
	if !withSetup && !withoutSetup {
		return nil, fmt.Errorf("external ID file header must be setup_id,account_id,action,external_id or account_id,action,external_id")
	}
	defaultSetupID = strings.TrimSpace(defaultSetupID)
	if withoutSetup && defaultSetupID == "" {
		return nil, fmt.Errorf("external ID file without setup_id requires exactly one selected setup")
	}

	assignments := make(externalIDAssignments)
	for row := 2; ; row++ {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read external ID file row %d: %w", row, err)
		}
		expectedFields := 3
		if withSetup {
			expectedFields = 4
		}
		if len(record) != expectedFields {
			return nil, fmt.Errorf("external ID file row %d has %d fields; expected %d", row, len(record), expectedFields)
		}
		for i := range record {
			record[i] = strings.TrimSpace(record[i])
		}
		setupID := defaultSetupID
		offset := 0
		if withSetup {
			setupID = record[0]
			offset = 1
		}
		accountID := record[offset]
		action := strings.ToLower(record[offset+1])
		externalID := record[offset+2]
		if setupID == "" {
			return nil, fmt.Errorf("external ID file row %d has an empty setup_id", row)
		}
		if !awsAccountIDPattern.MatchString(accountID) {
			return nil, fmt.Errorf("external ID file row %d has invalid AWS account ID %q; expected 12 digits", row, accountID)
		}
		switch action {
		case "set":
			if externalID == "" {
				return nil, fmt.Errorf("external ID file row %d uses action set but external_id is empty", row)
			}
		case "clear":
			if externalID != "" {
				return nil, fmt.Errorf("external ID file row %d uses action clear but external_id is not empty", row)
			}
		default:
			return nil, fmt.Errorf("external ID file row %d has invalid action %q; expected set or clear", row, action)
		}
		if assignments[setupID] == nil {
			assignments[setupID] = make(map[string]string)
		}
		if _, exists := assignments[setupID][accountID]; exists {
			return nil, fmt.Errorf("external ID file contains duplicate setup/account entry %s/%s", setupID, accountID)
		}
		assignments[setupID][accountID] = externalID
	}
	if len(assignments) == 0 {
		return nil, fmt.Errorf("external ID file contains no assignments")
	}
	return assignments, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
