# pair_ap
C client implementation of pairing for:
* Apple TV device verification, which became mandatory with tvOS 10.2 (this is
  called fruit mode in pair_ap)
* Homekit pairing (also for AirPlay 2)

Credit goes to @funtax and @ViktoriiaKh for doing some of the heavy lifting.

## Requirements
- libsodium
- libgcrypt or libopenssl
- libplist (only for Apple TV device verification)

To build the example client and server you also need libevent2. If the
dependencies are met you can build simply by running 'make'.

## Homekit pairing
Since I haven't been able to find much information on the internet on how
Homekit pairing is designed, here is a write-up of my current understanding. If
you know better, please help improve this.

With Homekit pairing, there may be a controller (e.g. the Home app), and a
number of devices/accessories (e.g. speakers). The controller acts as a client
and can make requests for pairing. After it is paired it can also add other
"third-party" pairings to the device, it can remove pairings and it can ask for
a list of pairings.

Other parties, e.g. the Music app or just iOS as an Airplay sender, can also
pair with devices/accesssories in a similar manner, but they are not full-
fledged Homekit controllers and thus don't make requests for adding, removing
or listing pairings.

The controller uses `/pair-add` to make sure that all devices on a network get
the ID and public key of all the other devices, so that the user only needs to
pair a device once.

### Normal pairing with one-time code
For a normal first-time pairing, the client needs a one-time code (the device
announces via mDNS whether a code is required). The client calls
`/pair-pin-start` and the device displays the code. There is also QR-based
pairing, which is (probably?) an encoded code.

After obtaining the code, the client initiates a three step `/pair-setup`
sequence, which results in both peers registering each other's ID and public
key. Henceforth, a pairing is verified with the two step `/pair-verify`, where
the parties check eachothers identify. Saving the peer's ID + public key isn't
strictly necessary if client or server doesn't care about verifying the peer,
i.e. that `/pair-setup` has actually been completed.

The result of `/pair-verify` is a shared secret that is used for symmetric
encryption of the following communication between the parties.

### Transient pairing
Some devices don't require a code from the user for pairing (e.g. an Airport
Express 2). If so, the client just needs to go through a two-step `/pair-setup`
sequence which results in a shared secret, which is then used for encrypted
communication. A fixed code of 3939 is used.

The controller can still use `/pair-add` etc. towards such devices.

## "fruit" pairing
Like normal Homekit pairing, this consists of first requesting a code with
`/pair-pin-start`, then a three-step `/pair-setup` and finally a two-step
`/pair-verify`. After that the communication is encrypted with the resulting
shared secret.


## Acknowledgments
- [AirPlayAuth](https://github.com/funtax/AirPlayAuth)
- [AirPlayAuth-ObjC](https://github.com/ViktoriiaKh/AirPlayAuth-ObjC)
- [ap2-sender](https://github.com/ViktoriiaKh/ap2-sender)
- [airplay2-receiver](https://github.com/ckdo/airplay2-receiver)
- [csrp](https://github.com/cocagne/csrp)
