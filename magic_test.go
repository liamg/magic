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

func TestLookupWithConfig(t *testing.T) {
	payload := []byte{31, 139, 8, 0, 130, 139, 110, 100, 2, 255, 61, 143, 65, 14, 131, 32, 20, 68, 247}

	workerCounts := []int{-1, 0, 1, 2, 10000}

	lookupConfigs := func(counts []int) []LookupConfig {
		configs := make([]LookupConfig, len(workerCounts)*2)
		for i := 0; i < len(counts)*2; i++ {
			configs[i] = LookupConfig{
				WorkerCount: counts[i%len(counts)],
			}
			if i < len(counts) {
				configs[i].ConcurrencyEnabled = true
			}
		}
		return configs
	}(workerCounts)

	for _, config := range lookupConfigs {
		fileType, err := LookupWithConfig(payload, config)
		require.Nil(t, err)
		assert.Equal(t, fileType.Extension, "gz")
	}

}

func TestLookupSync(t *testing.T) {

	fileType, err := LookupSync([]byte{0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x00, 0x00, 0x00})
	require.Nil(t, err)

	assert.Equal(t, fileType.Extension, "pcap")

}

func TestNestedLookupSync(t *testing.T) {

	fileType, err := LookupSync([]byte{0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x41, 0x56, 0x45})
	require.Nil(t, err)

	assert.Equal(t, fileType.Extension, "wav")
}
  
func TestLookupWithOffset(t *testing.T) {
	fileType, err := Lookup([]byte{0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x33, 0x67, 0x97})
	require.Nil(t, err)

	assert.Equal(t, fileType.Extension, "3gp")
}
