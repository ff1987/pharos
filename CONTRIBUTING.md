# Contributing to Pharos

Thanks for looking at a patch. Public development happens on
[github.com/ff1987/pharos](https://github.com/ff1987/pharos).

## Build and test

Rust 1.88+ (see `rust-toolchain.toml`). From a checkout:

```bash
bash scripts/ci.sh
```

That runs `cargo test --workspace --locked` and a release build. For tests only:

```bash
cargo test --workspace --locked
```

## Pull requests

- Open PRs against `main` on GitHub.
- Keep the wire protocol documented in `PROTOCOL.md`. Pharos is **not** an frp-compatible agent; do not add frp protocol compatibility.
- Prefer small, focused commits. Match the style of nearby code and docs (English for code comments and user-facing docs; Chinese is welcome in chat).
- Update `CHANGELOG.md` under `Unreleased` when the change is user-visible.
- Do not commit secrets, private keys, or real tokens. Lab configs under `examples/` stay throwaway.

## License

Contributions are accepted under the Apache-2.0 license (see [LICENSE](LICENSE)).
