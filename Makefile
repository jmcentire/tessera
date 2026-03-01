.PHONY: build test check fmt clippy clean

build:
	cargo build --workspace

test:
	cargo test --workspace

check: fmt clippy test

fmt:
	cargo fmt --check

clippy:
	cargo clippy --workspace -- -D warnings

clean:
	cargo clean

# WASM (Phase 2)
wasm:
	cd crates/tessera-wasm && wasm-pack build --target web
