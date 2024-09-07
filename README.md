# schnorr signatures + musig2 (N/N multisigs)

Simple zig implementation of [Schnorr Signatures](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) and [MuSig2](https://link.springer.com/chapter/10.1007/978-3-030-84242-0_8).

Implementation partially inspired by [https://github.com/VictoriaGrasshopper/schnorr_signature](https://github.com/VictoriaGrasshopper/schnorr_signature)

Includes a CLI app for independent/one-time using of schnorr and musig2 signing.

## Security considerations

TODO

## Installing

1. Run the following command:

```
zig fetch --save git+https://github.com/aidanaden/schnorr-zig
```

2. Add the following to `build.zig`:

```zig
const schnorr = b.dependency("schnorr", .{});
exe.root_module.addImport("schnorr", yazap.module("schnorr"));
```

## Build

```sh
zig build
```

## Usage

TODO

### CLI

TODO

### Code example

TODO

## API

This package exposes two functions: `generate` and `reconstruct`.

#### Generate

TODO

## License

Apache-2.0. See the [license file](LICENSE).

## References

- Reasons for Ristretto255

  - [https://loup-vaillant.fr/tutorials/cofactor](https://loup-vaillant.fr/tutorials/cofactor)

- Schnorr

  - [https://github.com/VictoriaGrasshopper/schnorr_signature](https://github.com/VictoriaGrasshopper/schnorr_signature)

- MuSig2

  - [https://hackmd.io/@_XlWbpTTRNaI4BeB7d8qig/BJbt-zlF_#Ristretto255](https://hackmd.io/@_XlWbpTTRNaI4BeB7d8qig/BJbt-zlF_#Ristretto255)
  - [https://eprint.iacr.org/2020/1261.pdf](https://eprint.iacr.org/2020/1261.pdf)

- Curve25519

  - [https://martin.kleppmann.com/papers/curve25519.pdf](https://martin.kleppmann.com/papers/curve25519.pdf)
