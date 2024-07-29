// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// BLSTx represents a transaction signed using BLS.
type BLSTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap  *big.Int // a.k.a. maxFeePerGas
	Gas        uint64
	To         *common.Address `rlp:"nil"` // nil means contract creation
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	PublicKey  []byte // a.k.a. Sender as specified in EIP-7591, in little-endian format
	Signature  []byte // bls.Signature
}

func (tx *BLSTx) copy() TxData {
	cpy := &BLSTx{
		Nonce:     tx.Nonce,
		To:        tx.To,
		Data:      common.CopyBytes(tx.Data),
		Gas:       tx.Gas,
		PublicKey: tx.PublicKey,
		Signature: common.CopyBytes(tx.Signature),

		// These are copied below.
		AccessList: make(AccessList, len(tx.AccessList)),
		Value:      new(big.Int),
		ChainID:    new(big.Int),
		GasTipCap:  new(big.Int),
		GasFeeCap:  new(big.Int),
	}
	copy(cpy.AccessList, tx.AccessList)
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	return cpy
}

// accessors for innerTx.
func (tx *BLSTx) txType() byte           { return BLSTxType }
func (tx *BLSTx) chainID() *big.Int      { return tx.ChainID }
func (tx *BLSTx) accessList() AccessList { return tx.AccessList }
func (tx *BLSTx) data() []byte           { return tx.Data }
func (tx *BLSTx) gas() uint64            { return tx.Gas }
func (tx *BLSTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *BLSTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *BLSTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *BLSTx) value() *big.Int        { return tx.Value }
func (tx *BLSTx) nonce() uint64          { return tx.Nonce }
func (tx *BLSTx) to() *common.Address    { return tx.To }
func (tx *BLSTx) publicKey() []byte      { return tx.PublicKey }
func (tx *BLSTx) signature() []byte      { return tx.Signature }
func (tx *BLSTx) isSystemTx() bool       { return false }

func (tx *BLSTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap)
	}
	tip := dst.Sub(tx.GasFeeCap, baseFee)
	if tip.Cmp(tx.GasTipCap) > 0 {
		tip.Set(tx.GasTipCap)
	}
	return tip.Add(tip, baseFee)
}

// Sets BLS signature
func (tx *BLSTx) setSignature(sig []byte) {
	tx.Signature = sig
}

// This is a no-op as we use BLS Signatures over ECDSA Signatures.
func (tx *BLSTx) rawSignatureValues() (v, r, s *big.Int) {
	return common.Big0, common.Big0, common.Big0
}

// This is also a no-op.
func (tx *BLSTx) setSignatureValues(chainID, _, _, _ *big.Int) {}

func (tx *BLSTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

func (tx *BLSTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}
