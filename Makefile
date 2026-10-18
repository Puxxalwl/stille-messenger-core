# stille-messenger — сборка через Zig (единственная зависимость: сам Zig 0.17)
ZIG ?= zig

.PHONY: build test run clean

build:
	cd core && $(ZIG) build -Doptimize=ReleaseFast

test:
	cd core && $(ZIG) build test --summary all

run: build
	cd core && ./zig-out/bin/stille-messenger-core chat

clean:
	rm -rf core/zig-out core/.zig-cache
