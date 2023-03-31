package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
)

// jwe.AgreementPartyUInfo and jwe.AgreementPartyVInfo

func PrepareBytes32(data []byte, toUint32Only bool) []byte {
	datalen := make([]byte, 4)
	if toUint32Only {
		dataVal, _ := strconv.Atoi(string(data))
		binary.BigEndian.PutUint32(datalen, uint32(dataVal))
		return datalen
	}
	binary.BigEndian.PutUint32(datalen, uint32(len(data)))
	return append(datalen, data...)
}

// Generate ephemeral ECDSA key pair
func GenerateCEK(ourEphemeralKey *ecdsa.PrivateKey, theirEphemeralKey *ecdsa.PublicKey) ([]byte, error) {

	// ECDH key agreement
	x, _ := theirEphemeralKey.Curve.ScalarMult(theirEphemeralKey.X, theirEphemeralKey.Y, ourEphemeralKey.D.Bytes())
	z := x.Bytes()
	//fmt.Println("z", z)

	// Concat KDF
	keylen := 16 // 128 bits
	algID := PrepareBytes32([]byte("A128GCM"), false)
	//fmt.Println("algID", algID)
	//fmt.Println("algID", PrepareBytes32([]byte("A128GCM"), false))

	//fmt.Println("A128GCM", []byte("A128GCM"))
	partyUInfo := PrepareBytes32([]byte("CardStandard"), false)
	//fmt.Println("partyUInfo", partyUInfo)
	partyVInfo := PrepareBytes32([]byte("0569"), false)
	//fmt.Println("partyVInfo", partyVInfo)
	suppPubInfo := PrepareBytes32([]byte("128"), true)
	//fmt.Println("suppPubInfo", suppPubInfo)
	otherInfo := append(algID, append(partyUInfo, partyVInfo...)...)
	otherInfo = append(otherInfo, suppPubInfo...)
	//fmt.Println("otherInfo", otherInfo)

	concatKDF := make([]byte, keylen)
	//hashInput := append([]byte{0, 0, 0, 1}, append(z[:], otherInfo...)...)
	hashInput := append(z[:], otherInfo...)
	h := sha256.Sum256(hashInput)
	copy(concatKDF, h[:keylen])
	//fmt.Println("concatKDF", concatKDF)

	cek := base64.RawURLEncoding.EncodeToString(concatKDF)
	fmt.Println("cek = ", cek)
	return concatKDF, nil
}
