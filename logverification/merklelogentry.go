package logverification

import (
	"encoding/json"
	"errors"

	"github.com/datatrails/go-datatrails-simplehash/go-datatrails-common-api-gen/assets/v2/assets"
	"google.golang.org/protobuf/encoding/protojson"
)

// MerklelogEntry safely decode the event json from the api and recovers the merkle log entry field
func MerklelogEntry(eventJson []byte) (*assets.MerkleLogEntry, error) {

	// Special care is needed because the protobuf to json conversion represents
	// uint64's as strings. And those do not round trip using a mix of generated
	// types and the generic json decoder.
	//
	// The pb -> json marshalsc a string encoded value. Then the decode to the
	// generated go lang type fails, because the generated type has uint64 and
	// the marshaled content is a string. The solution is to use the protojson
	// library rather than the generic json library. But this requires the
	// destination type be a protobuf generated type.
	//
	// That on its own solves the problem if the decoding of the MerklelogEntry
	// is defered via a custome type. Here, additionaly, we make use of a
	// generated type which accepts the structure of a datatrails event as it is
	// seen over the api surfiace.
	// Note: see the completeness demo for a different approach to this issue

	eventResp := struct {
		Identity       string          `json:"identity"`
		MerkleLogEntry json.RawMessage `json:"merklelog_entry"`
	}{}

	err := json.Unmarshal(eventJson, &eventResp)
	if err != nil {
		return nil, err
	}

	merkleLogEntry := assets.MerkleLogEntry{}
	err = protojson.Unmarshal(eventResp.MerkleLogEntry, &merkleLogEntry)
	if err != nil {
		return nil, err
	}

	return &merkleLogEntry, nil
}

// EventIdentity gets the event identity from the given event json
func EventIdentity(eventJson []byte) (string, error) {

	eventResp := map[string]any{}
	err := json.Unmarshal(eventJson, &eventResp)
	if err != nil {
		return "", err
	}

	identity, ok := eventResp["identity"].(string)
	if !ok {
		return "", errors.New("no identity found for event")
	}

	return identity, nil
}

// TenantIdentity gets the event's tenant identity from the given event json
func TenantIdentity(eventJson []byte) (string, error) {

	eventResp := map[string]any{}
	err := json.Unmarshal(eventJson, &eventResp)
	if err != nil {
		return "", err
	}

	tenantId, ok := eventResp["tenant_identity"].(string)
	if !ok {
		return "", errors.New("no tenant identity found for event")
	}

	return tenantId, nil
}
