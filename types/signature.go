package types

import (
	"bytes"
	"errors"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/keycard-go/apdu"
)

var (
	TagSignatureTemplate = uint8(0xA0)
	TagRawSignature      = uint8(0x80)
)

type Signature struct {
	pubKey []byte
	r      []byte
	s      []byte
	v      byte
}

func ParseSignature(message, resp []byte) (*Signature, error) {
	// check for old template first because TagRawSignature matches the pubkey tag
	template, err := apdu.FindTag(resp, apdu.Tag{TagSignatureTemplate})
	if err == nil {
		return parseLegacySignature(message, template)
	}

	sig, err := apdu.FindTag(resp, apdu.Tag{TagRawSignature})

	if err != nil {
		return nil, err
	}

	return ParseRecoverableSignature(message, sig)
}

func ParseRecoverableSignature(message, sig []byte) (*Signature, error) {
	if len(sig) != 65 {
		return nil, errors.New("invalid signature")
	}

	pubKey, err := crypto.Ecrecover(message, sig)
	if err != nil {
		return nil, err
	}

	return &Signature{
		pubKey: pubKey,
		r:      sig[0:32],
		s:      sig[32:64],
		v:      sig[64],
	}, nil
}

func DERSignatureToRS(tlv []byte) ([]byte, []byte, error) {
	r, err := apdu.FindTagN(tlv, 0, apdu.Tag{0x30}, apdu.Tag{0x02})
	if err != nil {
		return nil, nil, err
	}

	if len(r) > 32 {
		r = r[len(r)-32:]
	}

	s, err := apdu.FindTagN(tlv, 1, apdu.Tag{0x30}, apdu.Tag{0x02})
	if err != nil {
		return nil, nil, err
	}

	if len(s) > 32 {
		s = s[len(s)-32:]
	}

	return r, s, nil
}

func (s *Signature) PubKey() []byte {
	return s.pubKey
}

func (s *Signature) R() []byte {
	return s.r
}

func (s *Signature) S() []byte {
	return s.s
}

func (s *Signature) V() byte {
	return s.v
}

func parseLegacySignature(message, template []byte) (*Signature, error) {
	pubKey, err := apdu.FindTag(template, apdu.Tag{0x80})
	if err != nil {
		return nil, err
	}

	r, s, err := DERSignatureToRS(template)
	if err != nil {
		return nil, err
	}

	v, err := calculateV(message, pubKey, r, s)
	if err != nil {
		return nil, err
	}

	return &Signature{
		pubKey: pubKey,
		r:      r,
		s:      s,
		v:      v,
	}, nil
}

func calculateV(message, pubKey, r, s []byte) (v byte, err error) {
	rs := append(r, s...)
	for i := 0; i < 4; i++ {
		v = byte(i)
		sig := append(rs, v)
		rec, err := crypto.Ecrecover(message, sig)
		if err != nil {
			return v, err
		}

		if len(pubKey) == 33 {
			rec = compressPublicKey(rec)
		}

		if bytes.Equal(pubKey, rec) {
			return v, nil
		}
	}

	return v, err
}

func compressPublicKey(pubKey []byte) []byte {
	if len(pubKey) == 33 {
		return pubKey
	}

	if (pubKey[64] & 1) == 1 {
		pubKey[0] = 3
	} else {
		pubKey[0] = 2
	}

	return pubKey[0:33]
}
