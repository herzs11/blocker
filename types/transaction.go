package types

import (
	"crypto/sha256"

	"github.com/herzs11/blocker/crypto"
	"github.com/herzs11/blocker/proto"
	pb "google.golang.org/protobuf/proto"
)

func SignTransaction(pk *crypto.PrivateKey, tx *proto.Transaction) *crypto.Signature {
	return pk.Sign(HashTransaction(tx))
}

func HashTransaction(tx *proto.Transaction) []byte {
	b, err := pb.Marshal(tx)
	if err != nil {
		panic(err)
	}

	hash := sha256.Sum256(b)
	return hash[:]
}

func VerifyTransaction(tx *proto.Transaction) bool {
	for _, input := range tx.Inputs {
		pubKey := crypto.PublicKeyFromBytes(input.PublicKey)
		sig := crypto.SignatureFromBytes(input.Signature)
		// TODO: make sure we don't run into problems after verification
		input.Signature = nil
		if !sig.Verify(pubKey, HashTransaction(tx)) {
			return false
		}

	}
	return true
}
