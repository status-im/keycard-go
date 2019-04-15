package types

import "github.com/status-im/keycard-go/apdu"

// Channel is an interface with a Send method to send apdu commands and receive apdu responses.
type Channel interface {
	Send(*apdu.Command) (*apdu.Response, error)
}

type PairingInfo struct {
	Key   []byte
	Index int
}

var EXPORT_KEY_CURRENT                 = uint8(0x00)
var EXPORT_KEY_DERIVE                  = uint8(0x01)
var EXPORT_KEY_DERIVE_AND_MAKE_CURRENT = uint8(0x02)
var EXPORT_KEY_PRIV_PUB                = uint8(0x00)
var EXPORT_KEY_PUB                     = uint8(0x01)