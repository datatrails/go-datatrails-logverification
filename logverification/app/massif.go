package app

import (
	"context"
	"errors"
	"time"

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
