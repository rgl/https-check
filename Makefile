all: release

release:
	docker run \
		--rm \
		--volume $$PWD:/volume \
		--tty \
		clux/muslrust:1.64.0 \
		cargo build --release
	ls -laF ./target/x86_64-unknown-linux-musl/release/https-check
	ldd ./target/x86_64-unknown-linux-musl/release/https-check

clean:
	@# sudo because the container created the files as root.
	sudo rm -rf target

.PHONY: release clean
