package types

type ApplicationInfo struct {
	Installed      bool
	Initialized    bool
	InstanceUID    []byte
	PublicKey      []byte
	Version        []byte
	AvailableSlots []byte
	// KeyUID is the sha256 of of the master public key on the card.
	// It's empty if the card doesn't contain any key.
	KeyUID []byte
}

type ApplicationStatus struct {
	PinRetryCount    int
	PUKRetryCount    int
	KeyInitialized   bool
	PubKeyDerivation bool
}

type PairingInfo struct {
	Key   []byte
	Index int
}
