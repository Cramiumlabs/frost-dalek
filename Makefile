SRC := $(shell find src -type f -name '*.rs')
CARGO := Cargo.toml Cargo.lock
BIN := target/release/frost-cli

.PHONY: clean build-desktop build-desktop-force-alloc build-ac build-test test-desktop test-desktop-force-alloc run-test

clean:
	cargo clean

build-desktop: $(SRC) $(CARGO)
	cargo build --release --no-default-features --features "std" --lib

build-desktop-fixed-heap: $(SRC) $(CARGO)
	cargo build --release --no-default-features --features "std,fixed-heap,force-alloc" --lib

build-desktop-ac-heap: $(SRC) $(CARGO)
	cargo build --release --no-default-features --features "std,ac-heap,force-alloc" --lib

build-ac: $(SRC) $(CARGO)
	cargo build --release --target thumbv7em-none-eabi --no-default-features --features "alloc,ac-heap" --lib

$(BIN): $(SRC) $(CARGO)
	cargo build --release --bin frost-cli --no-default-features --features "std,ac-heap,force-alloc"

build-test: $(BIN)

test-desktop: $(SRC) $(CARGO)
	cargo test --no-default-features --features "std"

test-desktop-fixed-heap: $(SRC) $(CARGO)
	cargo test --no-default-features --features "std,fixed-heap,force-alloc"

test-desktop-ac-heap: $(SRC) $(CARGO)
	cargo test --no-default-features --features "std,ac-heap,force-alloc"

run-test-fixed-heap: $(SRC) $(CARGO)
	cargo build --release --bin frost-cli --no-default-features --features "std,fixed-heap,force-alloc"
	target/release/frost-cli

run-test-ac-heap: $(SRC) $(CARGO)
	cargo build --release --bin frost-cli --no-default-features --features "std,ac-heap,force-alloc"
	target/release/frost-cli
