set shell := ["bash", "-euo", "pipefail", "-c"]

patch:
  cargo release patch --no-publish --execute

publish:
  cargo publish

ci:
  cargo fmt --all --check
  cargo clippy --all-targets --all-features --locked -- -D warnings
  cargo doc --no-deps --all-features --locked
  cargo check --all-targets --all-features --locked
  cargo test --all-features --locked
  cargo test --no-default-features --locked
  cargo test --doc --all-features --locked
