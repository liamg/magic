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

func TestNestedLookup(t *testing.T) {

	fileType, err := Lookup([]byte{0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x41, 0x56, 0x45})
	require.Nil(t, err)

	assert.Equal(t, fileType.Extension, "wav")

}

func TestLookupWithOffset(t *testing.T) {
	fileType, err := Lookup([]byte{0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x33, 0x67, 0x97})
	require.Nil(t, err)

	assert.Equal(t, fileType.Extension, "3gp")
}
