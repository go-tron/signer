package signer

import (
	"crypto"
	_ "crypto/md5"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"fmt"
	"github.com/go-tron/crypto/encoding"
	"github.com/go-tron/crypto/rsaUtil"
	"github.com/go-tron/types/mapUtil"
)

type RsaKeyPair struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

type RSA struct {
	Key          RsaKeyPair
	SignProperty string
	Hash         crypto.Hash
	Encoding     encoding.Encoding
}

func NewRSA(rsaKey RsaKeyPair, signProperty string, hash crypto.Hash, encoding encoding.Encoding) *RSA {
	return &RSA{
		rsaKey, signProperty, hash, encoding,
	}
}

func DefaultRSAMd5Hex(rsaKey RsaKeyPair) *RSA {
	return NewRSA(rsaKey, "sign", crypto.MD5, &encoding.Hex{})
}
func DefaultRSASha1Hex(rsaKey RsaKeyPair) *RSA {
	return NewRSA(rsaKey, "sign", crypto.SHA1, &encoding.Hex{})
}
func DefaultRSASha256Hex(rsaKey RsaKeyPair) *RSA {
	return NewRSA(rsaKey, "sign", crypto.SHA256, &encoding.Hex{})
}
func DefaultRSAMd5Base64(rsaKey RsaKeyPair) *RSA {
	return NewRSA(rsaKey, "sign", crypto.MD5, &encoding.Base64{})
}
func DefaultRSASha1Base64(rsaKey RsaKeyPair) *RSA {
	return NewRSA(rsaKey, "sign", crypto.SHA1, &encoding.Base64{})
}
func DefaultRSASha256Base64(rsaKey RsaKeyPair) *RSA {
	return NewRSA(rsaKey, "sign", crypto.SHA256, &encoding.Base64{})
}

func (s *RSA) Sign(obj map[string]interface{}) error {
	signStr := mapUtil.ToSortString(obj)
	sign, err := rsaUtil.Sign(signStr, s.Key.Private, s.Hash, s.Encoding)
	if err != nil {
		return ErrorEncoding
	}
	obj[s.SignProperty] = sign
	return nil
}

func (s *RSA) Verify(obj map[string]interface{}) error {
	sign := obj[s.SignProperty]
	if sign == nil || sign.(string) == "" {
		return ErrorPresent
	}
	delete(obj, s.SignProperty)
	signStr := mapUtil.ToSortString(obj)
	if err := rsaUtil.Verify(signStr, fmt.Sprint(sign), s.Key.Public, s.Hash, s.Encoding); err != nil {
		return ErrorVerify
	} else {
		return nil
	}
}
