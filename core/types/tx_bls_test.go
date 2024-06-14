package types

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/holiman/uint256"
)

// key holds the BLS PublicKey and SecretKey for helper
// functions defined below
type key struct {
	pk *bls.PublicKey
	sk *bls.SecretKey
}

// Create a new BLS public and secret key
func newKey() (*key, error) {
	sk, err := bls.NewSecretKey()
	if err != nil {
		return nil, err
	}
	pk := bls.PublicFromSecretKey(sk)
	return &key{pk, sk}, nil
}

func (k *key) createEmptyBLSTx() (*Transaction, error) {
	blstx := k.createEmptyBLSTxInner()
	signer := NewBLSSigner(blstx.ChainID.ToBig())

	ecdsaSk, err := crypto.BLSToECDSAPrivateKey(k.sk)
	if err != nil {
		return nil, err
	}
	return MustSignNewTx(ecdsaSk, signer, blstx), nil
}

func (k *key) createEmptyBLSTxInner() *BLSTx {
	msg := make([]byte, 50)
	sig := bls.SignatureToBytes(bls.Sign(k.sk, msg))
	return &BLSTx{
		ChainID:   uint256.NewInt(1),
		Nonce:     5,
		GasTipCap: uint256.NewInt(22),
		GasFeeCap: uint256.NewInt(5),
		Gas:       25000,
		To:        common.Address{0x03, 0x04, 0x05},
		Value:     uint256.NewInt(99),
		Data:      msg,
		PublicKey: k.pk,
		Signature: sig,
	}
}

func TestBLSTxHashing(t *testing.T) {
	k, err := newKey()
	if err != nil {
		t.Fatal("error creating keys:", err)
	}
	tx, err := k.createEmptyBLSTx()
	if err != nil {
		t.Fatal("error creating empty BLSTx:", err)
	}
	hash := tx.Hash()
	t.Log("tx hash:", hash)
}
