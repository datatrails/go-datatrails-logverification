package integrationsupport

import (
	"crypto/ecdsa"
	"testing"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/datatrails/go-datatrails-common/cose"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
	"github.com/datatrails/go-datatrails-merklelog/mmrtesting"
	"github.com/stretchr/testify/require"
)

// GenerateMassifSeal is a test helper that generates a massif seal for testing purposes, using
// the test context.
func GenerateMassifSeal(t *testing.T, testContext mmrtesting.TestContext, lastEvent *assets.EventResponse, signingKey ecdsa.PrivateKey) {
	massifReader := massifs.NewMassifReader(logger.Sugar, testContext.Storer)

	// Just handle a single massif for now
	massifContext, err := massifReader.GetMassif(t.Context(), mmrtesting.DefaultGeneratorTenantIdentity, 0)
	require.Nil(t, err)

	mmrSize := massifContext.RangeCount()
	peaks, err := mmr.PeakHashes(&massifContext, mmrSize-1)
	require.Nil(t, err)
	id, epoch, err := massifs.SplitIDTimestampHex(lastEvent.MerklelogEntry.Commit.Idtimestamp)
	require.Nil(t, err)

	mmrState := massifs.MMRState{
		Version:         1,
		MMRSize:         mmrSize,
		Peaks:           peaks,
		CommitmentEpoch: uint32(epoch),
		IDTimestamp:     id,
	}

	codec, err := massifs.NewRootSignerCodec()
	require.Nil(t, err)

	signer := massifs.NewRootSigner("foobar", codec)
	coseSigner := cose.NewTestCoseSigner(t, signingKey)

	pubKey, err := coseSigner.LatestPublicKey()
	require.NoError(t, err)

	signedRootState, err := signer.Sign1(coseSigner, coseSigner.KeyIdentifier(), pubKey, "subject", mmrState, nil)
	require.Nil(t, err)

	blobPath := massifs.TenantMassifSignedRootPath(mmrtesting.DefaultGeneratorTenantIdentity, 0)
	_, err = testContext.Storer.Put(t.Context(), blobPath, azblob.NewBytesReaderCloser(signedRootState))
	require.Nil(t, err)
}
