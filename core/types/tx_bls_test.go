package types

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/holiman/uint256"
)

// Creates a dummy BLS transaction.
func createEmptyBLSTx(sk *bls.SecretKey) (*Transaction, error) {
	blstx := createEmptyBLSTxInner(5, sk)
	signer := NewBLSSigner(blstx.ChainID.ToBig())

	ecdsaPrivKey, err := crypto.BLSToECDSA(sk)
	if err != nil {
		return nil, err
	}
	return MustSignNewTx(ecdsaPrivKey, signer, blstx), nil
}

// Create the BLS txData.
func createEmptyBLSTxInner(nonce uint64, sk *bls.SecretKey) *BLSTx {
	return &BLSTx{
		ChainID:   uint256.NewInt(1),
		Nonce:     nonce,
		GasTipCap: uint256.NewInt(22),
		GasFeeCap: uint256.NewInt(5),
		Gas:       25000,
		To:        common.Address{0x03, 0x04, 0x05},
		Value:     uint256.NewInt(99),
		Data:      make([]byte, 50),
		PublicKey: bls.PublicFromSecretKey(sk),
	}
}

// Test to see if BLS signer works.
func TestBLSTxSigning(t *testing.T) {
	// Mimic wallet level
	k, err := crypto.GenerateBLSKey()
	if err != nil {
		t.Fatal("error creating keys:", err)
	}

	// Construct tx
	tx, err := createEmptyBLSTx(k)
	if err != nil {
		t.Fatal("error creating empty BLSTx:", err)
	}
	hash := tx.Hash()

	// Mimic wallet signing
	sig := bls.SignatureToBytes(bls.Sign(k, hash.Bytes()))
	tx.SetSignature(sig)
	t.Log("tx hash:", hash)
	if bytes.Equal(tx.Signature(), sig) {
		t.Fatal("BLS signature not the same")
	}
}

// Test BLS transaction size after marshal/unmarshal.
func TestBLSTxSize(t *testing.T) {
	// Create BLS key
	k, err := crypto.GenerateBLSKey()
	if err != nil {
		t.Fatal("error creating keys:", err)
	}

	// Setup ECDSA signer
	ecdsaPrivKey, err := crypto.BLSToECDSA(k)
	if err != nil {
		t.Fatal("error converting BLS to ECDSA private key:", err)
	}

	// Build and sign transaction
	txdata := createEmptyBLSTxInner(5, k)
	signer := NewBLSSigner(txdata.ChainID.ToBig())
	tx, err := SignNewTx(ecdsaPrivKey, signer, txdata)
	if err != nil {
		t.Fatal("error signing tx:", err)
	}
	bin, _ := tx.MarshalBinary()

	// Check initial calc
	if have, want := int(tx.Size()), len(bin); have != want {
		t.Errorf("size wrong, have %d want %d", have, want)
	}
	// Check cached version too
	if have, want := int(tx.Size()), len(bin); have != want {
		t.Errorf("(cached) size wrong, have %d want %d", have, want)
	}
	// Check unmarshalled version too
	utx := new(Transaction)
	if err := utx.UnmarshalBinary(bin); err != nil {
		t.Fatalf("failed to unmarshal tx: %v", err)
	}
	if have, want := int(utx.Size()), len(bin); have != want {
		t.Errorf("(unmarshalled) size wrong, have %d want %d", have, want)
	}
}

// Test BLS encoding/decoding for RLP and JSON.
func TestBLSTxCoding(t *testing.T) {
	k, err := crypto.GenerateBLSKey()
	if err != nil {
		t.Fatal("error creating keys:", err)
	}

	ecdsaPrivKey, err := crypto.BLSToECDSA(k)
	if err != nil {
		t.Fatal("error converting BLS to ECDSA private key:", err)
	}

	txdata := createEmptyBLSTxInner(5, k)
	signer := NewBLSSigner(txdata.ChainID.ToBig())
	tx, err := SignNewTx(ecdsaPrivKey, signer, txdata)
	if err != nil {
		t.Fatal("error signing tx:", err)
	}

	// RLP
	parsedTx, err := encodeDecodeBinary(tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := assertEqual(parsedTx, tx); err != nil {
		t.Fatal(err)
	}

	// JSON
	parsedTx, err = encodeDecodeJSON(tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := assertEqual(parsedTx, tx); err != nil {
		t.Fatal(err)
	}
}
