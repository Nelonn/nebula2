package handshake

import (
	"testing"

	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubtypeInfo(t *testing.T) {
	t.Run("HPKE0", func(t *testing.T) {
		info, err := subtypeInfoFor(header.HandshakeHPKE0)
		require.NoError(t, err)
		require.Len(t, info.msgs, 2)
		assert.True(t, info.msgs[0].expectsPayload)
		assert.True(t, info.msgs[0].expectsCert)
		assert.True(t, info.msgs[1].expectsPayload)
		assert.True(t, info.msgs[1].expectsCert)
	})

	t.Run("unknown subtype returns error", func(t *testing.T) {
		_, err := subtypeInfoFor(99)
		require.ErrorIs(t, err, ErrUnknownSubtype)
	})
}
