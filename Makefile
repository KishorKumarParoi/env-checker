.PHONY: test build install npm-test deploy clear

test:
	cargo test --workspace

build:
	cargo build --release

install: build
	cp target/release/env-checker /usr/local/bin/env-checker || cp target/release/env-checker ~/.cargo/bin/env-checker

npm-test:
	cd npm && npm test

deploy:
	./deploy.sh

clear:
	./clear.sh
