# solana-compiler-builtins

Compiler builtins optimized for the Solana Virtual Machine (SVM).

This crate provides SVM-optimized implementations of compiler-generated operations, including software implementations of intrinsics not natively supported by the SVM.

## Supported Symbols

| Category | Symbols |
| --- | --- |
| Memory | `memcmp`, `bcmp`, `memcpy`, `memmove`, `memset` |
| 128-bit integer arithmetic | `__multi3` |
| 64-bit floating-point arithmetic | `__adddf3`, `__subdf3`, `__negdf2`, `__muldf3`, `__divdf3` |
| 64-bit floating-point conversions | `__floatundidf`, `__fixunsdfdi` |
| 64-bit floating-point comparisons | `__gedf2`, `__gtdf2` |

## Contributing

Missing a compiler builtin or have an idea to improve performance? [Open an issue](https://github.com/blueshift-gg/solana-compiler-builtins/issues). Contributions are welcome!

## License

Licensed under the [MIT License](LICENSE).
