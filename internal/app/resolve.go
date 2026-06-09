package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

type NetworkChoice struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type NetworkSelectionError struct {
	Message   string          `json:"message"`
	Count     int             `json:"count"`
	Choices   []NetworkChoice `json:"choices"`
	Truncated bool            `json:"truncated"`
	UseFlag   string          `json:"use_flag"`
	Examples  []string        `json:"examples,omitempty"`
}

func (e *NetworkSelectionError) Error() string {
	return e.Message
}

func ResolveNetworkID(ctx context.Context, client *api.Client, networkID string) (string, error) {
	networkID = strings.TrimSpace(networkID)
	if networkID != "" {
		return networkID, nil
	}
	choices, err := NetworkChoices(ctx, client)
	if err != nil {
		return "", fmt.Errorf("resolve network ID: %w", err)
	}
	if len(choices) == 1 {
		return choices[0].ID, nil
	}
	if len(choices) == 0 {
		return "", &NetworkSelectionError{
			Message: "network ID is required, but no networks are visible to this user",
			UseFlag: "--network-id NETWORK_ID",
		}
	}
	return "", NewNetworkSelectionError(choices)
}

func NetworkChoices(ctx context.Context, client *api.Client) ([]NetworkChoice, error) {
	networks, err := client.Networks(ctx)
	if err != nil {
		return nil, err
	}
	choices := make([]NetworkChoice, 0, len(networks))
	for _, network := range networks {
		id := strings.TrimSpace(network.ID)
		if id == "" {
			continue
		}
		name := strings.TrimSpace(network.Name)
		choices = append(choices, NetworkChoice{ID: id, Name: name})
	}
	sort.Slice(choices, func(i, j int) bool {
		if choices[i].Name == choices[j].Name {
			return choices[i].ID < choices[j].ID
		}
		return strings.ToLower(choices[i].Name) < strings.ToLower(choices[j].Name)
	})
	return choices, nil
}

func NewNetworkSelectionError(choices []NetworkChoice) *NetworkSelectionError {
	if len(choices) == 0 {
		return &NetworkSelectionError{
			Message: "network ID is required, but no networks are visible to this user",
			UseFlag: "--network-id NETWORK_ID",
		}
	}
	examples := make([]string, 0, min(3, len(choices)))
	for _, choice := range choices {
		examples = append(examples, "--network-id "+choice.ID)
		if len(examples) == 3 {
			break
		}
	}
	visibleChoices := choices
	if len(visibleChoices) > 25 {
		visibleChoices = visibleChoices[:25]
	}
	return &NetworkSelectionError{
		Message:   "network ID is required because this user can see multiple networks",
		Count:     len(choices),
		Choices:   visibleChoices,
		Truncated: len(visibleChoices) < len(choices),
		UseFlag:   "--network-id NETWORK_ID",
		Examples:  examples,
	}
}
