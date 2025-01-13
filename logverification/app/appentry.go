package app

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-common/logger"
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

	IDTimestapSizeBytes = 8
)

// MMREntryFields are the fields that when hashed result in the MMR Entry
type MMREntryFields struct {

	// Domain defines the hashing schema for the MMR Entry
	Domain byte

	// SerializedBytes are app (customer) provided fields in the MMR Entry, serialized in a consistent way.
	SerializedBytes []byte
}

// AppEntry is the app provided data for a corresponding log entry.
//
// It contains key information for verifying inclusion of the corresponding log entry.
//
// NOTE: all fields are sourced from the app data, or derived from it.
// NONE of the fields in an AppEntry are sourced from the log.
type AppEntry struct {
	// AppId is an identifier of the app committing the merkle log entry
	AppId string

	// LogId is a uuid in byte form of the specific log identifier
	LogId []byte

	// ExtraBytes are extrabytes provided by datatrails for the specific app
	ExtraBytes []byte

	// MMREntryFields used to determine the MMR Entry
	MMREntryFields *MMREntryFields

	// MerkleLogCommit used to define information about the log entry
	MerkleLogCommit *assets.MerkleLogCommit

	// MerkleLogConfirm used to define information about the log seal
	MerkleLogConfirm *assets.MerkleLogConfirm
}

// NewAppEntry creates a new app entry entry
func NewAppEntry(
	appId string,
	logId []byte,
	extraBytes []byte,
	mmrEntryFields *MMREntryFields,
	merklelogCommit *assets.MerkleLogCommit,
) *AppEntry {

	verifiableLogEntry := &AppEntry{
		AppId:           appId,
		LogId:           logId,
		ExtraBytes:      extraBytes,
		MMREntryFields:  mmrEntryFields,
		MerkleLogCommit: merklelogCommit,
	}

	return verifiableLogEntry
}

// MMREntry derives the mmr entry of the corresponding log entry from the app data.
//
// MMREntry is:
//   - H( Domain | MMR Salt | Serialized Bytes)
func (ae *AppEntry) MMREntry() ([]byte, error) {

	hasher := sha256.New()

	// domain
	hasher.Write([]byte{ae.MMREntryFields.Domain})

	// mmr salt
	mmrSalt, err := ae.MMRSalt()
	if err != nil {
		return nil, err
	}

	hasher.Write(mmrSalt)

	// serialized bytes
	hasher.Write(ae.MMREntryFields.SerializedBytes)

	return hasher.Sum(nil), nil

}

// MMRIndex gets the mmr index of the corresponding log entry.
func (ae *AppEntry) MMRIndex() uint64 {
	return ae.MerkleLogCommit.Index
}

// MMRSalt derives the MMR Salt of the corresponding log entry from the app data.
// MMRSalt is the datatrails provided fields included on the MMR Entry.
//
// this is (extrabytes | idtimestamp) for any apps that adhere to log entry version 1.
func (ve *AppEntry) MMRSalt() ([]byte, error) {

	mmrSalt := make([]byte, MMRSaltSize)

	copy(mmrSalt[:24], ve.ExtraBytes)

	// get the byte representation of idtimestamp
	idTimestamp, _, err := massifs.SplitIDTimestampHex(ve.MerkleLogCommit.Idtimestamp)
	if err != nil {
		return nil, err
	}

	idTimestampBytes := make([]byte, IDTimestapSizeBytes)
	binary.BigEndian.PutUint64(idTimestampBytes, idTimestamp)

	copy(mmrSalt[24:], idTimestampBytes)

	return mmrSalt, nil
}

// LogTenant returns the Log tenant that committed this app entry to the log
// as a tenant identity.
func (ae *AppEntry) LogTenant() (string, error) {

	logTenantUuid, err := uuid.FromBytes(ae.LogId)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("tenant/%s", logTenantUuid.String()), nil

}

// Massif gets the massif context, for the massif of the corresponding log entry from the app data.
//
// The following massif options can be used, in priority order:
//   - WithMassifContext
//   - WithMassifReader
//   - WithAzblobReader
//
// Example WithMassifReader:
//
// WithMassifReader(
// reader,
// logverification.WithMassifTenantId("tenant/foo"),
// logverification.WithMassifHeight(14),
// )
func (ae *AppEntry) Massif(options ...MassifGetterOption) (*massifs.MassifContext, error) {

	massifOptions := ParseMassifGetterOptions(options...)

	// first check if the options give a massif context to use, and use that
	if massifOptions.massifContext != nil {
		return massifOptions.massifContext, nil
	}

	var massifReader MassifGetter
	// now check if we have a massif reader
	if massifOptions.massifReader != nil {
		massifReader = massifOptions.massifReader
	} else {
		// otherwise use azblob reader to get it
		if massifOptions.azblobReader == nil {
			return nil, errors.New("no way of determining massif of app entry, please provide either a massif context, massif reader or azblob reader")
		}

		newMassifReader := massifs.NewMassifReader(logger.Sugar, massifOptions.azblobReader)
		massifReader = &newMassifReader
	}

	massifHeight := massifOptions.MassifHeight

	logIdentity := massifOptions.TenantId
	// if the log identity is not given, attempt to find it from the logId
	if massifOptions.TenantId == "" {
		// find the tenant log from the logID
		logUuid, err := uuid.FromBytes(ae.LogId)
		if err != nil {
			return nil, err
		}

		// log identity is currently `tenant/logid`
		logIdentity = fmt.Sprintf("tenant/%s", logUuid.String())
	}

	return Massif(ae.MerkleLogCommit.Index, massifReader, logIdentity, massifHeight)

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
