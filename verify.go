package httpsig

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

type verifier func(string, []byte) (bool, error)

// VerifySignature takes a ParsedSignature and a public key, and validates that
// the signature was signed with the given algorithm and a corresponding private
// key.
func VerifySignature(parsedSignature *ParsedSignature, pubKey string) (bool, error) {
	v, err := getVerifier(parsedSignature.Algorithm(), pubKey)
	if err != nil {
		return false, err
	}
	sig, err := base64.StdEncoding.DecodeString(parsedSignature.Signature())
	if err != nil {
		return false, err
	}
	return v(parsedSignature.SigningString(), sig)
}

func hmacVerifier(secret string, hash crypto.Hash) verifier {
	return func(data string, sig []byte) (bool, error) {
		h := hmac.New(hash.New, []byte(secret))
		h.Write([]byte(data))
		expected := h.Sum(nil)
		return bytes.Equal(expected, sig), nil
	}
}

func rsaVerifier(key *rsa.PublicKey, hash crypto.Hash) verifier {
	return func(data string, sig []byte) (bool, error) {
		hashed := calcHash(data, hash)
		err := rsa.VerifyPKCS1v15(key, hash, hashed, sig)
		return err == nil, err
	}
}

func getVerifier(algorithm string, pubKey string) (verifier, error) {
	alg, err := validateAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	if alg.sign == "hmac" {
		return hmacVerifier(pubKey, alg.hash), nil
	}
	k, err := getPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	switch key := k.(type) {
	case *rsa.PublicKey:
		if alg.sign != "rsa" {
			return nil, fmt.Errorf("Algorithm %s doesn't match public key of type %T", algorithm, key)
		}
		return rsaVerifier(key, alg.hash), nil
	}
	return nil, fmt.Errorf("unsupported signing algorithm: %s", algorithm)
}

func getPublicKey(key string) (interface{}, error) {
	block, _ := pem.Decode([]byte(key))
	return x509.ParsePKIXPublicKey(block.Bytes)
}
