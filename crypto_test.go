package crypto_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/filecoin-project/go-crypto"
)

func TestGenerateKey(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	sk, err := crypto.GenerateKey()
	assert.NoError(t, err)

	assert.Equal(t, len(sk), 32)

	msg := generateMsg(32)

	digest, err := crypto.Sign(sk, msg)
	assert.NoError(t, err)
	assert.Equal(t, len(digest), 65)
	pk := crypto.PublicKey(sk)

	// valid signature
	assert.True(t, crypto.Verify(pk, msg, digest))

	// invalid signature - different message (too short)
	assert.False(t, crypto.Verify(pk, msg[3:], digest))

	// invalid signature - different message
	msg2 := make([]byte, 32)
	copy(msg2, msg)
	rand.Shuffle(len(msg2), func(i, j int) { msg2[i], msg2[j] = msg2[j], msg2[i] })
	assert.False(t, crypto.Verify(pk, msg2, digest))

	// invalid signature - different digest
	digest2 := make([]byte, 65)
	copy(digest2, digest)
	rand.Shuffle(len(digest2), func(i, j int) { digest2[i], digest2[j] = digest2[j], digest2[i] })
	assert.False(t, crypto.Verify(pk, msg, digest2))

	// invalid signature - digest too short
	assert.False(t, crypto.Verify(pk, msg, digest[3:]))
	assert.False(t, crypto.Verify(pk, msg, digest[:29]))

	// invalid signature - digest too long
	digest3 := make([]byte, 70)
	copy(digest3, digest)
	assert.False(t, crypto.Verify(pk, msg, digest3))

	recovered, err := crypto.EcRecover(msg, digest)
	assert.NoError(t, err)
	assert.Equal(t, recovered, crypto.PublicKey(sk))
}

func TestECRecoverInvalidMsgLength(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	sk, _ := crypto.GenerateKey()

	// create three different message lengths for testing
	shortMsg := generateMsg(31)
	correctMsg := generateMsg(32)
	longMsg := generateMsg(33)

	// even though we sign the regular message, the msg length error should trigger first
	digest, err := crypto.Sign(sk, correctMsg)
	assert.NoError(t, err)
	assert.Equal(t, len(digest), 65)

	_, err = crypto.EcRecover(shortMsg, digest)
	if assert.Error(t, err) {
		assert.Equal(t, crypto.ErrInvalidMsgLength, err)
	}

	_, err = crypto.EcRecover(longMsg, digest)
	if assert.Error(t, err) {
		assert.Equal(t, crypto.ErrInvalidMsgLength, err)
	}

	_, err = crypto.EcRecover(correctMsg, digest)
	assert.NoError(t, err)
}

func TestECRecoverInvalidRecoveryID(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	sk, _ := crypto.GenerateKey()

	msg := generateMsg(32)

	// even though we sign the regular message, the msg length error should trigger first
	digest, err := crypto.Sign(sk, msg)
	assert.NoError(t, err)
	assert.Equal(t, len(digest), 65)

	// valid recovery
	pk, err := crypto.EcRecover(msg, digest)
	assert.NoError(t, err)
	assert.Equal(t, pk, crypto.PublicKey(sk))

	// change the recovery ID to an invalid value
	digest[64] = 4
	_, err = crypto.EcRecover(msg, digest)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "secp256k1: invalid recovery ID")
	}
}

func generateMsg(msgLength uint) []byte {
	msg := make([]byte, msgLength)
	for i := 0; i < len(msg); i++ {
		msg[i] = byte(i)
	}
	return msg
}
