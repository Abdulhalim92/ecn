package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"log"
	"math/big"
	"os"
	"strings"
)

func main() {

	curve := elliptic.P256()
	ourPrivateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}
	ourPublicKey := ourPrivateKey.PublicKey

	//serverX, serverY := getXandY("eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkFKWWF0STVmZE5DOFZpZC1qZUI4azZKZjBqSUh2QVVtOXYtWkFiWTRiSVY1IiwieSI6IkFLeUtXY2hfWWtyYXlnS3JOeGJyclpSeEVlTlVoSU5CS3RuNFZRRmpvVjZnIn0")
	// Create the JWE header
	ourPublicKeyJwk := EPK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(ourPublicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(ourPublicKey.Y.Bytes()),
	}
	fmt.Println("pub = ", ourPublicKeyJwk.MakePub())

	jwe := "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIiwicHViIjoiZXlKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SWxBdE1qVTJJaXdpZUNJNklrRktXV0YwU1RWbVpFNURPRlpwWkMxcVpVSTRhelpLWmpCcVNVaDJRVlZ0T1hZdFdrRmlXVFJpU1ZZMUlpd2llU0k2SWtGTGVVdFhZMmhmV1d0eVlYbG5TM0pPZUdKeWNscFNlRVZsVGxWb1NVNUNTM1J1TkZaUlJtcHZWalpuSW4wIn0..wSAC7p32_pMndBkq.KAtKxIEmlW9T72l8bJI.mfMXZH2q0Pby1BEGeUz5jQ"
	jwe = ""
	fmt.Println("Input JWE:")
	fmt.Scan(&jwe)
	file, err := os.Open("jwe.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		jwe = scanner.Text()
	}
	//fmt.Println("scanned jwe = ", jwe)

	//send request with pub

	resCamRS := strings.Split(jwe, ".")
	if len(resCamRS) != 5 {
		fmt.Println("res JWE format error")
		return
	}
	header, err := base64.RawURLEncoding.DecodeString(resCamRS[0])
	fmt.Println("header =", string(header))

	//encrypted_key_if_present, err := base64.RawURLEncoding.DecodeString(resCamRS[1])

	iv, err := base64.RawURLEncoding.DecodeString(resCamRS[2])
	//fmt.Println("iv =", string(iv))

	ciphertext, err := base64.RawURLEncoding.DecodeString(resCamRS[3])
	//fmt.Println("ciphertext =", string(ciphertext))

	//auth_tag, err := base64.RawURLEncoding.DecodeString(resCamRS[4])
	//fmt.Println("auth_tag =", string(auth_tag))

	var jweHeader JweHeader
	if err = json.Unmarshal(header, &jweHeader); err != nil {
		fmt.Println("jweHeader Unmarshal error")
		return
	}
	theirJWK, err := base64.RawURLEncoding.DecodeString(jweHeader.Pub)
	theirPublicEPK, err := jwk.ParseKey(theirJWK)
	theirPublicEpkXKey, _ := theirPublicEPK.Get(jwk.ECDSAXKey)
	theirPublicEpkYKey, _ := theirPublicEPK.Get(jwk.ECDSAYKey)
	theirPublicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(theirPublicEpkXKey.([]byte)), //big.NewInt(0).SetBytes([]byte(theirEphemeralPublicKeyAsJwk["x"].(string)))
		Y:     new(big.Int).SetBytes(theirPublicEpkYKey.([]byte)),
	}
	cek, _ := GenerateCEK(ourPrivateKey, theirPublicKey)
	//fmt.Println("cek = ", cek)

	iv1 := make([]byte, 12)
	if _, err := rand.Read(iv1); err != nil {
		fmt.Printf("failed to generate IV: %w", err)
	}

	// Encode data as JSON
	plaintext := []byte(`{"cvc2": "123"}`)
	if err != nil {
		fmt.Printf("failed to encode data: %w", err)
	}

	// Create AEAD cipher with CEK and IV
	block1, err := aes.NewCipher(cek)
	if err != nil {
		fmt.Printf("failed to create cipher: %w", err)
	}
	gcm1, err := cipher.NewGCM(block1)
	if err != nil {
		fmt.Printf("failed to create AEAD cipher: %w    ", err)
	}
	//auth_tag1 := gcm1.Seal(nil, iv1, []byte{}, nil)
	// Encrypt plaintext with AEAD cipher
	ciphertext1 := gcm1.Seal(nil, iv1, plaintext, header)
	fmt.Printf("iv  %s\n", resCamRS[2])
	fmt.Printf("iv1 %s\n", base64.RawURLEncoding.EncodeToString(iv1))

	fmt.Printf("ciphertext  %s\n", resCamRS[3])
	fmt.Printf("ciphertext1 %s\n", base64.RawURLEncoding.EncodeToString(ciphertext1))

	fmt.Printf("auth_tag  %s\n", resCamRS[4])
	fmt.Printf("auth_tag1 %s\n", base64.RawURLEncoding.EncodeToString(gcm1.Seal(nil, iv, []byte{}, nil)))
	fmt.Printf("auth_tag1 %s\n", base64.RawURLEncoding.EncodeToString(gcm1.Seal(nil, iv, []byte{}, header)))
	fmt.Printf("auth_tag1 %s\n", base64.RawURLEncoding.EncodeToString(gcm1.Seal(nil, iv, []byte{}, []byte(resCamRS[0]))))

	// Create AEAD cipher with CEK and IV
	block, err := aes.NewCipher(cek)
	if err != nil {
		fmt.Printf("failed to create cipher: %x", err)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("failed to create AEAD cipher: %x    ", err)
		return
	}

	// -----------------------------------------------------
	//stream := cipher.NewCTR(block, iv)
	//plainText := make([]byte, len(ciphertext))
	//stream.XORKeyStream(plainText, ciphertext)
	//fmt.Println(plainText)

	decr, err := gcm.Open(nil, iv, ciphertext, []byte(resCamRS[0]))
	if err != nil {
		fmt.Printf("1. failed to decrypt JWE: %v\n", err.Error())
		decr, err = gcm.Open(nil, iv, ciphertext, []byte(resCamRS[0]))
		if err != nil {
			fmt.Printf("2. failed to decrypt JWE: %v\n", err.Error())
			decr, err = gcm.Open(nil, iv, ciphertext, []byte(`{"alg":"dir","enc":"A128GCM"}`))
			if err != nil {
				fmt.Printf("3. failed to decrypt JWE: %v\n", err.Error())
				decr, err = gcm.Open(nil, iv, ciphertext, []byte(base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"dir","enc":"A128GCM"}`))))
				if err != nil {
					fmt.Printf("4. failed to decrypt JWE: %v\n", err.Error())
					return
				}
				return
			}
			return
		}
		return
	}
	fmt.Println("decr", string(decr))

}

type JweHeader struct {
	Alg string `json:"alg"`
	Enc string `json:"enc"`
	Pub string `json:"pub"`
}

type EPK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (keyStruct EPK) MakePub() string {
	sample, _ := json.Marshal(keyStruct)
	encodedStringURL := base64.RawURLEncoding.EncodeToString(sample)
	//fmt.Printf("pub= %v\n", encodedStringURL)
	return encodedStringURL
}
