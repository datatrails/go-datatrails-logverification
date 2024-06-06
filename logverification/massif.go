package logverification

import (
	"context"
	"errors"
	"time"

	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
)

const (
	contextTimeout = 30 * time.Second
)

var (
	ErrNilMassifContext = errors.New("nil massif context")
)

// handleMassifIndexErr handles the massifIndex error from the mmrIndex
//
//	based on whether we suppress NotLeaf node errors or not.
//
// If we want to suppress NotLeaf errors, return all errors but ErrNotLeaf
//
//	otherwise return all errors.
func handleMassifIndexErr(err error, nonLeafNode bool) error {

	if !nonLeafNode {
		return err
	}

	if !errors.Is(err, massifs.ErrNotleaf) {
		return err
	}

	// if we get here its a ErrNotLeaf and we want to suppress this error
	return nil
}

// Massif gets the massif (blob) that contains the given mmrIndex, from azure blob storage
//
//	defined by the azblob configuration.
func Massif(mmrIndex uint64, massifReader massifs.MassifReader, tenantId string, massifHeight uint8, opts ...MassifOption) (*massifs.MassifContext, error) {

	massifOptions := ParseMassifOptions(opts...)

	massifIndex, err := massifs.MassifIndexFromMMRIndex(massifHeight, mmrIndex)

	// handle the error and if we want to suppress NotLeaf errors
	err = handleMassifIndexErr(err, massifOptions.nonLeafNode)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	massif, err := massifReader.GetMassif(ctx, tenantId, massifIndex)
	if err != nil {
		return nil, err
	}

	return &massif, nil
}

// MassifFromEvent gets the massif (blob) that contains the given event, from azure blob storage
//
//	defined by the azblob configuration.
func MassifFromEvent(eventJson []byte, reader azblob.Reader, options ...MassifOption) (*massifs.MassifContext, error) {

	massifOptions := ParseMassifOptions(options...)

	// 1. get the massif (blob) index from the merkleLogEntry on the event
	merkleLogEntry, err := MerklelogEntry(eventJson)
	if err != nil {
		return nil, err
	}

	massifHeight := massifOptions.massifHeight

	// if tenant ID is not supplied
	//  we should find it based on the given eventJson
	tenantId := massifOptions.tenantId
	if tenantId == "" {
		tenantId, err = TenantIdentity(eventJson)
		if err != nil {
			return nil, err
		}
	}

	massifReader := massifs.NewMassifReader(logger.Sugar, reader)

	return Massif(merkleLogEntry.Commit.Index, massifReader, tenantId, massifHeight)
}

// ChooseHashingSchema chooses the hashing schema based on the log version in the massif blob start record.
// See [Massif Basic File Format](https://github.com/datatrails/epic-8120-scalable-proof-mechanisms/blob/main/mmr/forestrie-massifs.md#massif-basic-file-format)
func ChooseHashingSchema(massifStart massifs.MassifStart) (EventHasher, error) {

	switch massifStart.Version {
	case 0:
		return NewLogVersion0Hasher(), nil
	default:
		return nil, errors.New("no hashing scheme for log version")
	}
}

// UpdateMassifContext, updates the given massifContext to the massif that stores
//
//	the given mmrIndex for the given tenant.
//
// A Massif is a blob that contains a portion of the merkle log.
// A MassifContext is the context used to get specific massifs.
func UpdateMassifContext(massifReader massifs.MassifReader, massifContext *massifs.MassifContext, mmrIndex uint64, tenantID string, massifHeight uint8) error {

	// there is a chance here that massifContext is nil, in this case we can't do anything
	//  as we set the massifContext as a side effect, and there is no pointer value.
	if massifContext == nil {
		return ErrNilMassifContext
	}

	// check if the current massifContext contains the given mmrIndex
	if mmrIndex >= massifContext.Start.FirstIndex && mmrIndex < massifContext.LastLeafMMRIndex() {
		return nil
	}

	// if we get here, we know that we need a different massifContext to the given massifContext

	nextContext, err := Massif(mmrIndex, massifReader, tenantID, massifHeight)
	if err != nil {
		return err
	}

	*massifContext = *nextContext
	return nil
}
