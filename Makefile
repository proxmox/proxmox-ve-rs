# Shortcut for common operations:

CRATES != echo proxmox-*/Cargo.toml | sed -e 's|/Cargo.toml||g'

# By default we just run checks:
.PHONY: all
all: check

.PHONY: deb
deb: $(foreach c,$(CRATES), $c-deb)
	echo $(foreach c,$(CRATES), $c-deb)
	lintian build/*.deb

.PHONY: dsc
dsc: $(foreach c,$(CRATES), $c-dsc)
	echo $(foreach c,$(CRATES), $c-dsc)
	lintian build/*.dsc

.PHONY: autopkgtest
autopkgtest: $(foreach c,$(CRATES), $c-autopkgtest)

.PHONY: dinstall
dinstall:
	$(MAKE) clean
	$(MAKE) deb
	sudo -k dpkg -i build/librust-*.deb

%-deb:
	./build.sh $*
	touch $@

%-dsc:
	BUILDCMD='dpkg-buildpackage -S -us -uc -d' ./build.sh $*
	touch $@

%-autopkgtest:
	autopkgtest build/$* build/*.deb -- null
	touch $@

.PHONY: check
check:
	cargo test

# Prints a diff between the current code and the one rustfmt would produce
.PHONY: fmt
fmt:
	cargo +nightly fmt -- --check

# Doc without dependencies
.PHONY: doc
doc:
	cargo doc --no-deps

.PHONY: clean
clean:
	cargo clean
	rm -rf build/
	rm -f -- *-deb *-dsc *-autopkgtest *.build *.buildinfo *.changes

.PHONY: update
update:
	cargo update

%-upload: %-deb
	cd build; \
	    dcmd --deb rust-$*_*.changes \
	    | grep -v '.changes$$' \
	    | tar -cf "$@.tar" -T-; \
	    cat "$@.tar" | ssh -X repoman@repo.proxmox.com upload --product devel --dist bookworm
