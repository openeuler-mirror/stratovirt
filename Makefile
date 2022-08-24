.PHONY: build
build: yum-deps
	cargo build --release

.PHONY: install
install:
	cargo install --locked --path .

.PHONY: clean
clean:
	cargo clean

yum-deps:
	@yum install pixman-devel
