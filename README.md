# Yggdrasil Vanity

Vanity address generator for the Yggdrasil network

## Basic usage (just search high addresses)

```shell
cargo run --release
```

## Regex matching

Pass -r "regex" argument (you can do it multiple times of you want search for multiple patterns) to search only for adresses matching given regex.

Example:

```shell
cargo run --release -- -r "" -r "^([0-9a-f]*:){2}:" -r "^([0-9a-f]*:){2}[0-9a-f]{0,2}:0:" -r "^([0-9a-f]*:){3}0:" -r "1234:5678"
```

## Benchmarks

- AMD Radeon RX 6800 XT: 25 MH/s


## Credits
- [nano-vanity](https://github.com/PlasmaPower/nano-vanity) for ed25519 OpenCL kernel
- [opencl_brute](https://github.com/bkerler/opencl_brute) for sha512 OpenCL kernel
