package lightwallet

type ApplicationInfo struct {
	InstanceUID    []byte
	PublicKey      []byte
	Version        []byte
	AvailableSlots []byte
	// KeyUID is the sha256 of of the master public key on the card.
	// It's empty if the card doesn't contain any key.
	KeyUID []byte
}

type PairingInfo struct {
	PairingKey   []byte
	PairingIndex int
}
