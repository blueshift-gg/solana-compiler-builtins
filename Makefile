NIGHTLY_TOOLCHAIN := nightly

.PHONY: nightly-version format clippy program-test

nightly-version:
	@echo $(NIGHTLY_TOOLCHAIN)

format:
	@cargo +$(NIGHTLY_TOOLCHAIN) fmt --all -- --check

clippy:
	@cargo +$(NIGHTLY_TOOLCHAIN) clippy --all --all-features --all-targets -- -D warnings

program-test:
	@cd program-test && cargo +$(NIGHTLY_TOOLCHAIN) build-bpf && cargo test

