package logverification

import (
	"context"
	"errors"
	"time"

	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-logverification/logverification/app"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
)

const (
	contextTimeout = 30 * time.Second
)

var (
	ErrNilMassifContext = errors.New("nil massif context")
)

type MassifGetter interface {
	GetMassif(
		ctx context.Context, tenantIdentity string, massifIndex uint64, opts ...massifs.ReaderOption,
	) (massifs.MassifContext, error)
}

// Massif gets the massif (blob) that contains the given mmrIndex, from azure blob storage
//
//	defined by the azblob configuration.
func Massif(mmrIndex uint64, massifReader MassifGetter, tenantId string, massifHeight uint8) (*massifs.MassifContext, error) {

	massifIndex := massifs.MassifIndexFromMMRIndex(massifHeight, mmrIndex)

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	massif, err := massifReader.GetMassif(ctx, tenantId, massifIndex)
	if err != nil {
		return nil, err
	}

	return &massif, nil
}

// MassifFromEvent gets the massif (blob) that contains the given event, from azure blob storage
// defined by the azblob configuration.
func MassifFromEvent(verifiableEvent *app.AssetsV2AppEntry, reader azblob.Reader, options ...MassifOption) (*massifs.MassifContext, error) {
	massifOptions := ParseMassifOptions(options...)
	massifHeight := massifOptions.MassifHeight

	// if tenant ID is not supplied, find it based on the given eventJson
	tenantId := massifOptions.TenantId
	if tenantId == "" {

		var err error
		tenantId, err = verifiableEvent.LogTenant()
		if err != nil {
			return nil, err
		}
	}

	massifReader := massifs.NewMassifReader(logger.Sugar, reader)
	return Massif(verifiableEvent.MerkleLogCommit.Index, &massifReader, tenantId, massifHeight)
}

// ChooseHashingSchema chooses the hashing schema based on the log version in the massif blob start record.
// See [Massif Basic File Format](https://github.com/datatrails/epic-8120-scalable-proof-mechanisms/blob/main/mmr/forestrie-massifs.md#massif-basic-file-format)
func ChooseHashingSchema(massifStart massifs.MassifStart) (EventHasher, error) {

	switch massifStart.Version {
	case 0:
		return app.NewLogVersion0Hasher(), nil
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
func UpdateMassifContext(massifReader MassifGetter, massifContext *massifs.MassifContext, mmrIndex uint64, tenantID string, massifHeight uint8) error {

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
