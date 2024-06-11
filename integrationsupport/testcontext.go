//go:build integration && azurite

package integrationsupport

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	dtcose "github.com/datatrails/go-datatrails-common/cose"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-merklelog/mmrtesting"
	"github.com/datatrails/go-datatrails-simplehash/simplehash"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func NewAzuriteTestContext(
	t *testing.T,
	testLabelPrefix string,
) (mmrtesting.TestContext, TestGenerator, mmrtesting.TestConfig) {
	cfg := mmrtesting.TestConfig{
		StartTimeMS: (1698342521) * 1000, EventRate: 500,
		TestLabelPrefix: testLabelPrefix,
		TenantIdentity:  "",
		Container:       strings.ReplaceAll(strings.ToLower(testLabelPrefix), "_", "")}
	leafHasher := NewLeafHasher()
	tc := mmrtesting.NewTestContext(t, cfg)
	g := NewTestGenerator(
		t, cfg.StartTimeMS/1000,
		&leafHasher,
		mmrtesting.TestGeneratorConfig{
			StartTimeMS:     cfg.StartTimeMS,
			EventRate:       cfg.EventRate,
			TenantIdentity:  cfg.TenantIdentity,
			TestLabelPrefix: cfg.TestLabelPrefix,
		},
	)
	return tc, g, cfg
}

// GenerateTenantLog populates the tenants blob storage with deterministically generated
//
// datatrails merklelog events as leaf nodes, and populates the rest of the mmr
// from these leaf nodes.
//
// Returns the list of generated events with the correct merklelog data.
//
// NOTE: deletes all pre-existing blobs for the given tenant first.
// NOTE: Will only populate the first massif.
// NOTE: No Range checks are performed if you go out of the first massif.
func GenerateTenantLog(tc *mmrtesting.TestContext, g TestGenerator, eventTotal int, tenantID string, deleteBlobs bool, massifHeight uint8) []*assets.EventResponse {

	if deleteBlobs {
		// first delete any blobs already in the massif
		tc.DeleteBlobsByPrefix(massifs.TenantMassifPrefix(tenantID))
	}

	c := massifs.NewMassifCommitter(
		massifs.MassifCommitterConfig{
			CommitmentEpoch: 1, /* good until 2038 for real. irrelevant for tests as long as everyone uses the same value */
		},
		tc.GetLog(),
		tc.GetStorer(),
	)

	mc, err := c.GetCurrentContext(context.Background(), tenantID, massifHeight)
	if err != nil {
		tc.T.Fatalf("unexpected err: %v", err)
	}

	g.LeafHasher.Reset()

	batch := g.GenerateEventBatch(eventTotal)

	events := []*assets.EventResponse{}
	for _, ev := range batch {

		// get next timestamp id
		idTimestamp, err1 := g.NextId()
		require.Nil(tc.T, err1)

		// now hash the generated event
		hasher := simplehash.NewHasherV3()

		// hash the generated event
		err1 = hasher.HashEvent(
			ev,
			simplehash.WithPrefix([]byte{byte(LeafTypePlain)}),
			simplehash.WithIDCommitted(idTimestamp))
		require.Nil(tc.T, err1)

		// get the leaf value (hash of event)
		leafValue := hasher.Sum(nil)

		// mmrIndex is equal to the count of all nodes
		mmrIndex := mc.RangeCount()

		// add the generated event to the mmr
		_, err1 = mc.AddHashedLeaf(sha256.New(), idTimestamp, []byte(ev.TenantIdentity), []byte(ev.GetIdentity()), leafValue)
		if err1 != nil {
			if errors.Is(err1, massifs.ErrMassifFull) {
				var err2 error
				_, err2 = c.CommitContext(context.Background(), mc)
				require.Nil(tc.T, err2)

				// We've filled the current massif. GetCurrentContext handles creating new massifs.
				mc, err2 = c.GetCurrentContext(context.Background(), tenantID, massifHeight)
				if err2 != nil {
					tc.T.Fatalf("unexpected err: %v", err)
				}

				_, err1 = mc.AddHashedLeaf(sha256.New(), idTimestamp, []byte(ev.TenantIdentity), []byte(ev.GetIdentity()), leafValue)
			}

			require.Nil(tc.T, err1)
		}

		// set the events merklelog entry correctly
		ev.MerklelogEntry = &assets.MerkleLogEntry{
			Commit: &assets.MerkleLogCommit{
				Index:       mmrIndex,
				Idtimestamp: massifs.IDTimestampToHex(idTimestamp, uint8(c.Cfg.CommitmentEpoch)),
			},
		}

		events = append(events, ev)
	}

	_, err = c.CommitContext(context.Background(), mc)
	require.Nil(tc.T, err)

	return events
}

func NewCoseSignerForECPrivateKey(t *testing.T, key ecdsa.PrivateKey) *cose.Signer {
	alg, err := dtcose.CoseAlgForEC(key.PublicKey)
	require.NoError(t, err)

	signer, err := cose.NewSigner(alg, &key)
	require.NoError(t, err)

	return &signer
}
