package signer

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"github.com/go-estar/crypto/encoding"
	"github.com/go-estar/types/mapUtil"
)

type Hash struct {
	Key          string
	KeyProperty  string
	SignProperty string
	Hash         crypto.Hash
	Encoding     encoding.Encoding
}

func NewHash(key string, keyProperty string, signProperty string, hash crypto.Hash, encoding encoding.Encoding) *Hash {
	return &Hash{
		key, keyProperty, signProperty, hash, encoding,
	}
}

func DefaultHashMd5Hex(key string) *Hash {
	return NewHash(key, "key", "sign", crypto.MD5, &encoding.Hex{})
}
func DefaultHashSha1Hex(key string) *Hash {
	return NewHash(key, "key", "sign", crypto.SHA1, &encoding.Hex{})
}
func DefaultHashSha256Hex(key string) *Hash {
	return NewHash(key, "key", "sign", crypto.SHA256, &encoding.Hex{})
}

func DefaultHashMd5Base64(key string) *Hash {
	return NewHash(key, "key", "sign", crypto.MD5, &encoding.Base64{})
}
func DefaultHashSha1Base64(key string) *Hash {
	return NewHash(key, "key", "sign", crypto.SHA1, &encoding.Base64{})
}
func DefaultHashSha256Base64(key string) *Hash {
	return NewHash(key, "key", "sign", crypto.SHA256, &encoding.Base64{})
}

func (h *Hash) Sign(obj map[string]interface{}) error {
	signStr := mapUtil.ToSortString(obj)
	signStr += "&" + h.KeyProperty + "=" + h.Key

	hashMethod := h.Hash.New()
	hashMethod.Write([]byte(signStr))
	sign := h.Encoding.EncodeToString(hashMethod.Sum(nil))
	obj[h.SignProperty] = sign
	return nil
}

func (h *Hash) Verify(obj map[string]interface{}) error {
	sign := obj[h.SignProperty]
	if sign == nil {
		return ErrorPresent
	}
	delete(obj, h.SignProperty)

	h.Sign(obj)
	if obj[h.SignProperty] != sign {
		return ErrorVerify
	} else {
		return nil
	}
}
