# pair_ap
C client implementation of pairing for:
* Apple TV device verification, which became mandatory with tvOS 10.2 (this is
  called fruit mode in pair_ap)
* Homekit pairing (for AirPlay 2)

Credit goes to @funtax and @ViktoriiaKh for doing some of the heavy lifting.
## Requirements
- libsodium
- libgcrypt or libopenssl
- libplist (only for Apple TV device verification)

To build the example client and server you also need libevent2. If the
dependencies are met you can build simply by running 'make'.

## Acknowledgments
- [AirPlayAuth](https://github.com/funtax/AirPlayAuth)
- [AirPlayAuth-ObjC](https://github.com/ViktoriiaKh/AirPlayAuth-ObjC)
- [ap2-sender](https://github.com/ViktoriiaKh/ap2-sender)
- [csrp](https://github.com/cocagne/csrp)
