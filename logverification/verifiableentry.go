package logverification

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/google/uuid"
)

/**
 * Verifiable :Log Entry is a Log Entry that can be verified.
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

type MassifGetter interface {
	GetMassif(
		ctx context.Context, tenantIdentity string, massifIndex uint64, opts ...massifs.ReaderOption,
	) (massifs.MassifContext, error)
}

// MMREntryFields are the fields that when hashed result in the MMR Entry
type MMREntryFields struct {

	// Domain defines the hashing schema for the MMR Entry
	Domain byte

	// SerializedBytes are app (customer) provided fields in the MMR Entry, serialized in a consistent way.
	SerializedBytes []byte
}

// VerifiableLogEntry contains key information for verifying inclusion and consistency of merkle log entries
type VerifiableLogEntry struct {
	// AppId is an identifier of the app committing the merkle log entry
	AppId string

	// AppId is a uuid in byte form of the specific log identifier
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

// NewVerifiableLogEntry creates a new verifiable log entry
func NewVerifiableLogEntry(
	appId string,
	logId []byte,
	extraBytes []byte,
	mmrEntryFields *MMREntryFields,
	merklelogCommit *assets.MerkleLogCommit,
	opts ...VerifiableLogEntryOption,
) *VerifiableLogEntry {

	verifiableLogEntry := &VerifiableLogEntry{
		AppId:           appId,
		LogId:           logId,
		ExtraBytes:      extraBytes,
		MMREntryFields:  mmrEntryFields,
		MerkleLogCommit: merklelogCommit,
	}

	// get all the options
	verifiableLogEntryOptions := ParseVerifableLogEntryOptions(opts...)
	verifiableLogEntry.MerkleLogConfirm = verifiableLogEntryOptions.merkleLogConfirm

	return verifiableLogEntry
}

// MMREntry gets the mmr entry of a verifiable log entry
//
// MMREntry is:
//   - H( Domain | MMR Salt | Serialized Bytes)
func (vle *VerifiableLogEntry) MMREntry() ([]byte, error) {

	hasher := sha256.New()

	// domain
	hasher.Write([]byte{vle.MMREntryFields.Domain})

	// mmr salt
	mmrSalt, err := vle.MMRSalt()
	if err != nil {
		return nil, err
	}

	hasher.Write(mmrSalt)

	// serialized bytes
	hasher.Write(vle.MMREntryFields.SerializedBytes)

	return hasher.Sum(nil), nil

}

// MMRIndex gets the mmr index of the verifiable log entry
func (vle *VerifiableLogEntry) MMRIndex() uint64 {
	return vle.MerkleLogCommit.Index
}

// MMRSalt gets the MMR Salt, which is the datatrails provided fields included on the MMR Entry.
//
// this is (extrabytes | idtimestamp) for any apps that adhere to log entry version 1.
func (ve *VerifiableLogEntry) MMRSalt() ([]byte, error) {

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

// massif gets the massif context for the VerifiableLogEntry.
func (vle *VerifiableLogEntry) massif(reader MassifGetter, options ...MassifOption) (*massifs.MassifContext, error) {

	massifOptions := ParseMassifOptions(options...)
	massifHeight := massifOptions.massifHeight

	// find the tenant log from the logID
	logUuid, err := uuid.FromBytes(vle.LogId)
	if err != nil {
		return nil, err
	}

	// log identity is currently `tenant/logid`
	logIdentity := fmt.Sprintf("tenant/%s", logUuid.String())

	return Massif(vle.MerkleLogCommit.Index, reader, logIdentity, massifHeight)

}

// VerifyInclusion verifies the inclusion of the verifiable log entry
// against the immutable merkle log, acquired using the given reader.
//
// Returns true if the event is included on the log, otherwise false.
func (vle *VerifiableLogEntry) VerifyInclusion(reader MassifGetter, options ...MassifOption) (bool, error) {

	massif, err := vle.massif(reader, options...)

	if err != nil {
		return false, err
	}

	proof, err := EventProof(vle, massif)
	if err != nil {
		return false, err
	}

	return VerifyProof(vle, proof, massif)
}
