.PHONY: clean build-desktop build-ac test-desktop

clean:
	cargo clean

build-desktop:
	cargo build --release --no-default-features --features "std,u64_backend" --lib

build-desktop-force-alloc:
	cargo build --release --no-default-features --features "std,u64_backend,force-alloc" --lib

build-ac:
	cargo build --release --target thumbv7em-none-eabi --no-default-features --features "alloc,u64_backend" --lib

test-desktop:
	cargo test --no-default-features --features "std,u64_backend"

test-desktop-force-alloc:
	cargo test --no-default-features --features "std,u64_backend,force-alloc"