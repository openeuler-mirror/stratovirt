.PHONY: build
build:
	cargo build

.PHONY: install
install:
	cargo install --locked --path .

.PHONY: clean
clean:
	cargo clean
