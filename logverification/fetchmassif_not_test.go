package logverification

import (
	"context"
	"fmt"
	"testing"

	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/stretchr/testify/assert"
)

func TestFetchMassif(t *testing.T) {
	logger.New("NOOP")

	reader, err := azblob.NewReaderNoAuth(
		"https://app.qa.stage.datatrails.ai/verifiabledata",
		azblob.WithContainer("merklelogs"),
	)
	assert.NoError(t, err)

	massifReader := massifs.NewMassifReader(logger.Sugar, reader)

	massifContext, err := massifReader.GetFirstMassif(context.Background(), "tenant/112758ce-a8cb-4924-8df8-fcba1e31f8b0")
	assert.NoError(t, err)

	var i uint64
	for i = 0; i < 10; i++ {
		mmrEntry, err := massifContext.Get(i)
		assert.NoError(t, err)

		trieEntry, err := massifContext.GetTrieEntry(i)
		assert.NoError(t, err)

		fmt.Printf("MMR Index %d ------- \n", i)
		fmt.Println("MMR Entry:")
		fmt.Println(mmrEntry)
		fmt.Println("ExtraBytes:")
		fmt.Println(massifs.GetExtraBytes(trieEntry, 0, 0))
		fmt.Println("IDTimestamp:")
		fmt.Println(massifs.GetIdtimestamp(trieEntry, 0, 0))
	}
}
