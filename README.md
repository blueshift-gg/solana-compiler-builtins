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

## Overriding a builtin

Enable the `weak-linkage` feature to declare the builtins `weak_odr`. You can then replace any of them by defining the same symbol in your program or in one of its dependencies, as LLVM takes a strong definition over a weak one:

```toml
solana-compiler-builtins = { version = "0.2", features = ["weak-linkage"] }
```

```rust
#[unsafe(no_mangle)]
pub unsafe fn __multi3(a: i128, b: i128) -> i128 {
    // ...
}
```

Match the ABI of the definition you are replacing. `extern "C"` passes `i128` indirectly on this target, so `__multi3` has to use the Rust ABI; the `f64` builtins are `extern "C"`.

Without the feature the builtins are strong, as they have always been, and a second definition of one is a `symbol multiply defined` link error.

## Contributing

Missing a compiler builtin or have an idea to improve performance? [Open an issue](https://github.com/blueshift-gg/solana-compiler-builtins/issues). Contributions are welcome!

## License

Licensed under the [MIT License](LICENSE).
