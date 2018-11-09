# status-hardware-wallet

`status-hardware-wallet` is a command line tool you can use to initialize a [Status Hardware Wallet](https://github.com/status-im/hardware-wallet).

## Installation

`go get github.com/status-im/hardware-wallet-go/cmd/status-hardware-wallet`

## Usage

### Install the hardware wallet applet

The install command will install an applet to the card.
You can download the status `cap` file from the (status-im/hardware-wallet releases page)[https://github.com/status-im/hardware-wallet/releases].

```bash
status-hardware-wallet install -l debug -a PATH_TO_CAP_FILE
```

In case the applet is already installed and you want to force a new installation you can pass the `-f` flag.

### Card info

```bash
status-hardware-wallet info -l debug
```

The `info` command will print something like this:

```
Installed: true
Initialized: false
InstanceUID: 0x
PublicKey: 0x112233...
Version: 0x
AvailableSlots: 0x
KeyUID: 0x<Paste>
```

### Card initialization


```bash
status-hardware-wallet init -l debug
```

The `init` command initializes the card and generates the secrets needed to pair the card to a device.
The output

```
PIN 123456
PUK 123456789012
Pairing password: RandomPairingPassword
```

### Pairing

```bash
status-hardware-wallet pair -l debug
```

The process will ask for `PairingPassword` and `PIN` and will generate a pairing key you can use to interact with the card.
