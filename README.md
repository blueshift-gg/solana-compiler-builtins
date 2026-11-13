# solana-compiler-builtins

Compiler builtins optimized for the Solana Virtual Machine (SVM).

This crate provides SVM-optimized implementations of compiler-generated operations, including software implementations of intrinsics not natively supported by the SVM.

## Supported Symbols

| Category | Symbols |
| --- | --- |
| Memory | `memcmp`, `bcmp`, `memcpy`, `memmove`, `memset` |
| 128-bit integer arithmetic | `__multi3`, `__udivti3`, `__umodti3` |
| 32-bit floating-point arithmetic | `__addsf3`, `__subsf3`, `__mulsf3`, `__divsf3` |
| 32-bit floating-point conversions | `__floatunsisf`, `__floatsisf`, `__floatdisf`, `__floatundisf`, `__fixsfsi`, `__fixunssfsi` |
| 32-bit floating-point comparisons | `__ltsf2`, `__lesf2`, `__eqsf2`, `__nesf2`, `__gtsf2`, `__gesf2`, `__unordsf2` |
| 64-bit floating-point arithmetic | `__adddf3`, `__subdf3`, `__negdf2`, `__muldf3`, `__divdf3` |
| 64-bit floating-point conversions | `__floatundidf`, `__floatunsidf`, `__floatdidf`, `__floatsidf`, `__fixunsdfdi`, `__fixdfdi`, `__fixdfsi`, `__fixunsdfsi` |
| 64-bit floating-point comparisons | `__gedf2`, `__gtdf2`, `__ltdf2`, `__ledf2`, `__eqdf2`, `__nedf2`, `__unorddf2` |

## Overriding a builtin

Enable the `weak-linkage` feature to declare the builtins `weak_odr`. You can then replace any of them by defining the same symbol in your program or in one of its dependencies, as LLVM takes a strong definition over a weak one:

```toml
solana-compiler-builtins = { version = "0.3", features = ["weak-linkage"] }
```

```rust
#[unsafe(no_mangle)]
pub unsafe fn __multi3(a: i128, b: i128) -> i128 {
    // ...
}
```

Without the feature, builtins are strong so a second definition will result in a `symbol multiply defined` link error.

## Contributing

Missing a compiler builtin or have an idea to improve performance? [Open an issue](https://github.com/blueshift-gg/solana-compiler-builtins/issues). Contributions are welcome!

## License

Licensed under the [MIT License](LICENSE).
