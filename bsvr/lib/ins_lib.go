package lib

import (
	"encoding/hex"
	"fmt"

	"github.com/Univ-Wyo-Education/S21-4010-a04/bsvr/addr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pschlump/godebug"
)

func ValidSignature(sig SignatureType, msg string, from addr.AddressType) bool {
	fmt.Printf("AT: %s\n", godebug.LF())
	// TODO - xyzyz - we will validate signatures in the "Wallet" homework.  AS-05.
	// return true
	// }
	// VerifySignature takes hex encoded addr, sig and msg and verifies that the signature matches with the address.
	// Pulled form go-ethereum code.
	// func VerifySignature2(addr, sig, msg string) (recoveredAddress, recoveredPublicKey string, err error) {
	message, err := hex.DecodeString(msg)
	if err != nil {
		// return "", "", fmt.Errorf("unabgle to decode message (invalid hex data) Error:%s", err)
		return false
	}
	fmt.Printf("AT: %s\n", godebug.LF())
	//	if !common.IsHexAddress(addr) {
	//		return "", "", fmt.Errorf("invalid address: %s", addr)
	//	}
	// fmt.Printf("AT: %s\n", godebug.LF())
	// address := common.HexToAddress(addr)
	address := common.HexToAddress(fmt.Sprintf("%x", from))
	signature, err := hex.DecodeString(string(sig))
	if err != nil {
		// return "", "", fmt.Errorf("signature is not valid hex Error:%s", err)
		return false
	}
	fmt.Printf("AT: %s\n", godebug.LF())

	recoveredPubkey, err := crypto.SigToPub(signHash(message), signature)
	if err != nil || recoveredPubkey == nil {
		// return "", "", fmt.Errorf("signature verification failed Error:%s", err)
		return false
	}
	fmt.Printf("AT: %s\n", godebug.LF())
	recoveredPublicKey := hex.EncodeToString(crypto.FromECDSAPub(recoveredPubkey))
	rawRecoveredAddress := crypto.PubkeyToAddress(*recoveredPubkey)
	if address != rawRecoveredAddress {
		// return "", "", fmt.Errorf("signature did not verify, addresses did not match")
		return false
	}
	fmt.Printf("AT: %s\n", godebug.LF())
	recoveredAddress := rawRecoveredAddress.Hex()
	_ = recoveredAddress
	_ = recoveredPublicKey
	// return
	return true
}

// signHash is a helper function that calculates a hash for the given message
// that can be safely used to calculate a signature from.
//
// The hash is calulcated as
//   keccak256("\x19Ethereum Signed Message:\n"${message length}${message}).
//
// This gives context to the signed message and prevents signing of transactions.
func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}
