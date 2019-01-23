package magic

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestLookup(t *testing.T) {

	fileType, err := Lookup([]byte{0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x00, 0x00, 0x00})
	require.Nil(t, err)

	assert.Equal(t, fileType.Extension, "pcap")

}
