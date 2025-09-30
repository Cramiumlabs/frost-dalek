SRC := $(shell find src -type f -name '*.rs')
CARGO := Cargo.toml Cargo.lock
BIN := target/release/frost-cli

.PHONY: clean build-desktop build-desktop-force-alloc build-ac build-test test-desktop test-desktop-force-alloc run-test

clean:
	cargo clean

build-desktop: $(SRC) $(CARGO)
	cargo build --release --no-default-features --features "std,u64_backend" --lib

build-desktop-force-alloc: $(SRC) $(CARGO)
	cargo build --release --no-default-features --features "std,u64_backend,force-alloc" --lib

build-ac: $(SRC) $(CARGO)
	cargo build --release --target thumbv7em-none-eabi --no-default-features --features "alloc,u64_backend" --lib

# frost-cli binary rule
$(BIN): $(SRC) $(CARGO)
	cargo build --release --bin frost-cli --no-default-features --features "std,u64_backend,force-alloc"

# build-test now just points to the binary
build-test: $(BIN)

test-desktop: $(SRC) $(CARGO)
	cargo test --no-default-features --features "std,u64_backend"

test-desktop-force-alloc: $(SRC) $(CARGO)
	cargo test --no-default-features --features "std,u64_backend,force-alloc"

run-test: build-test
	$(BIN)
