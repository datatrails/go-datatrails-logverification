package app

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
	"github.com/google/uuid"
)

/**
 * AppEntry is the app provided data for a corresponding log entry.
 * An AppEntry will derive fields used for log entry inclusion verification.
 *
 * The format for an MMR entry is the following:
 *
 * H( Domain | MMR Salt | Serialized Bytes)
 *
 * Where:
 *   * Domain           - the hashing schema for the MMR Entry
 *   * MMR Salt         - datatrails provided fields included in the MMR Entry (can be found in the corresponding Trie Value on the log)
 *   * Serialized Bytes - app (customer) provided fields in the MMR Entry, serialized in a consistent way.
 *
 *
 * The format for a Trie Entry is the following:
 *
 * ( Trie Key | Trie Value )
 *
 * Where the Trie Key is:
 *
 * H( Domain | LogId | AppId )
 *
 * And Trie Value is:
 *
 * ( Extra Bytes | IdTimestamp )
 */

const (
	MMRSaltSize = 32

	ExtraBytesSize = 24

	IDTimestapSizeBytes = 8
)

// MMREntryFields are the fields that when hashed result in the MMR Entry
type MMREntryFields struct {

	// domain defines the hashing schema for the MMR Entry
	domain byte

	// serialized bytes is the serialized bytes that get hashed as part of the MMR Entry
	serializedBytes []byte
}

func NewMMREntryFields(domain byte, serializedBytes []byte) *MMREntryFields {
	return &MMREntryFields{
		domain:          domain,
		serializedBytes: serializedBytes,
	}
}

// AppEntry is the app provided data for a corresponding log entry.
//
// It contains key information for verifying inclusion of the corresponding log entry.
//
// NOTE: all fields are sourced from the app data, or derived from it.
// NONE of the fields in an AppEntry are sourced from the log.
type AppEntry struct {
	// appID is an identifier of the app committing the merkle log entry
	appID string

	// logID is a uuid in byte form of the specific log identifier
	logID []byte

	// MMREntryFields used to determine the MMR Entry
	mmrEntryFields *MMREntryFields

	// mmrIndex of the corresponding log entry
	mmrIndex uint64
}

// NewAppEntry creates a new app entry entry
func NewAppEntry(
	appId string,
	logId []byte,
	mmrEntryFields *MMREntryFields,
	mmrIndex uint64,
) *AppEntry {

	appEntry := &AppEntry{
		appID:          appId,
		logID:          logId,
		mmrEntryFields: mmrEntryFields,
		mmrIndex:       mmrIndex,
	}

	return appEntry
}

// AppID gets the app id of the corresponding log entry.
func (ae *AppEntry) AppID() string {
	return ae.appID
}

// LogID gets the log id of the corresponding log entry.
func (ae *AppEntry) LogID() []byte {
	return ae.logID
}

// Domain gets the domain byte used to derive the mmr entry.
func (ae *AppEntry) Domain() byte {
	return ae.mmrEntryFields.domain
}

// SerializedBytes gets the serialized bytes used to generate hash of the corresponding mmr entry.
func (ae *AppEntry) SerializedBytes() []byte {
	return ae.mmrEntryFields.serializedBytes
}

// MMRIndex gets the mmr index of the corresponding log entry.
func (ae *AppEntry) MMRIndex() uint64 {
	return ae.mmrIndex
}

// LogTenant returns the Log tenant that committed this app entry to the log
// as a tenant identity.
func (ae *AppEntry) LogTenant() (string, error) {

	logTenantUuid, err := uuid.FromBytes(ae.logID)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("tenant/%s", logTenantUuid.String()), nil

}

// TrieEntry gets the corresponding log trie entry for the app entry.
func (ae *AppEntry) TrieEntry(options ...MassifGetterOption) ([]byte, error) {

	massifContext, err := ae.Massif(options...)
	if err != nil {
		return nil, err
	}

	trieEntry, err := massifContext.GetTrieEntry(ae.MMRIndex())
	if err != nil {
		return nil, err
	}

	return trieEntry, nil

}

// ExtraBytes gets the extrabytes of the corresponding log entry.
func (ae *AppEntry) ExtraBytes(options ...MassifGetterOption) ([]byte, error) {

	trieEntry, err := ae.TrieEntry(options...)
	if err != nil {
		return nil, err
	}

	return massifs.GetExtraBytes(trieEntry, 0, 0), nil
}

// IDTimestamp gets the idtimestamp of the corresponding log entry.
func (ae *AppEntry) IDTimestamp(options ...MassifGetterOption) ([]byte, error) {

	trieEntry, err := ae.TrieEntry(options...)
	if err != nil {
		return nil, err
	}

	return massifs.GetIdtimestamp(trieEntry, 0, 0), nil
}

// MMRSalt derives the MMR Salt of the corresponding log entry from the app data.
// MMRSalt is the datatrails provided fields included on the MMR Entry.
//
// this is (extrabytes | idtimestamp) for any apps that adhere to log entry version 1.
func (ae *AppEntry) MMRSalt(options ...MassifGetterOption) ([]byte, error) {

	mmrSalt := make([]byte, MMRSaltSize)

	extraBytes, err := ae.ExtraBytes(options...)
	if err != nil {
		return nil, err
	}

	idTimestamp, err := ae.IDTimestamp(options...)
	if err != nil {
		return nil, err
	}

	copy(mmrSalt[:ExtraBytesSize], extraBytes)

	copy(mmrSalt[ExtraBytesSize:], idTimestamp)

	return mmrSalt, nil
}

// MMREntry derives the mmr entry of the corresponding log entry from the app data.
//
// MMREntry is:
//   - H( Domain | MMR Salt | Serialized Bytes)
//
// The MMR Salt is sourced from the corresponding log entry
func (ae *AppEntry) MMREntry(options ...MassifGetterOption) ([]byte, error) {

	logVersion0 := true

	// first find the log version
	massifContext, err := ae.Massif(options...)
	if err != nil {
		return nil, err
	}

	extraBytes, err := ae.ExtraBytes(WithMassifContext(massifContext))
	if err != nil {
		return nil, err
	}

	// the only implementation of log version 0 is assetsv2
	//  so check for the assetsv2 app domain (0).
	if extraBytes[0] != 0 {
		logVersion0 = false
	}

	if logVersion0 {
		hasher := LogVersion0Hasher{}

		var idTimestamp []byte
		idTimestamp, err = ae.IDTimestamp(WithMassifContext(massifContext))
		if err != nil {
			return nil, err
		}

		var eventHash []byte
		eventHash, err = hasher.HashEvent(ae.mmrEntryFields.serializedBytes, idTimestamp)
		if err != nil {
			return nil, err
		}

		return eventHash, nil
	}

	// if we get here we know its a log version 1 entry

	hasher := sha256.New()

	// domain
	hasher.Write([]byte{ae.mmrEntryFields.domain})

	// mmr salt
	mmrSalt, err := ae.MMRSalt()
	if err != nil {
		return nil, err
	}

	hasher.Write(mmrSalt)

	// serialized bytes
	hasher.Write(ae.mmrEntryFields.serializedBytes)

	return hasher.Sum(nil), nil

}

/** Massif gets the massif context, for the massif of the corresponding log entry from the app data.
 *
 * The following massif options can be used, in priority order:
 *   - WithMassifContext
 *   - WithMassifReader
 *
 * Example WithMassifReader:
 *
 * WithMassifReader(
 *   reader,
 *   WithMassifTenantId("tenant/foo"),
 *   WithMassifHeight(14),
 * )
 */
func (ae *AppEntry) Massif(options ...MassifGetterOption) (*massifs.MassifContext, error) {

	massifOptions := ParseMassifGetterOptions(options...)

	// first check if the options give a massif context to use, and use that
	if massifOptions.massifContext != nil {
		return massifOptions.massifContext, nil
	}

	// now check if we have a massif reader
	if massifOptions.massifGetter == nil {
		return nil, errors.New("no way of determining massif of app entry, please provide either a massif context or massif getter")

	}

	massifReader := massifOptions.massifGetter
	massifHeight := massifOptions.MassifHeight

	logIdentity := massifOptions.TenantId
	// if the log identity is not given, attempt to find it from the logId
	if massifOptions.TenantId == "" {
		// find the tenant log from the logID
		logUuid, err := uuid.FromBytes(ae.logID)
		if err != nil {
			return nil, err
		}

		// log identity is currently `tenant/logid`
		logIdentity = fmt.Sprintf("tenant/%s", logUuid.String())
	}

	return Massif(ae.mmrIndex, massifReader, logIdentity, massifHeight)

}

// Proof gets the inclusion proof of the corresponding log entry for the app data.
func (ae *AppEntry) Proof(options ...MassifGetterOption) ([][]byte, error) {

	massif, err := ae.Massif(options...)

	if err != nil {
		return nil, err
	}

	// Get the size of the complete tenant MMR
	mmrSize := massif.RangeCount()

	proof, err := mmr.InclusionProof(massif, mmrSize-1, ae.MMRIndex())
	if err != nil {
		return nil, err
	}

	return proof, nil
}

// VerifyProof verifies the given inclusion proof of the corresponding log entry for the app data.
func (ae *AppEntry) VerifyProof(proof [][]byte, options ...MassifGetterOption) (bool, error) {

	massif, err := ae.Massif(options...)

	if err != nil {
		return false, err
	}

	// Get the size of the complete tenant MMR
	mmrSize := massif.RangeCount()

	hasher := sha256.New()

	mmrEntry, err := ae.MMREntry()
	if err != nil {
		return false, err
	}

	return mmr.VerifyInclusion(massif, hasher, mmrSize, mmrEntry,
		ae.MMRIndex(), proof)

}

// VerifyInclusion verifies the inclusion of the app entry
// against the corresponding log entry in immutable merkle log
//
// Returns true if the app entry is included on the log, otherwise false.
func (ae *AppEntry) VerifyInclusion(options ...MassifGetterOption) (bool, error) {

	massif, err := ae.Massif(options...)

	if err != nil {
		return false, err
	}

	proof, err := ae.Proof(WithMassifContext(massif))
	if err != nil {
		return false, err
	}

	return ae.VerifyProof(proof, WithMassifContext(massif))
}
