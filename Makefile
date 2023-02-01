prog :=impersonate-rs

cargo := $(shell command -v cargo 2> /dev/null)
cargo_v := $(shell cargo -V| cut -d ' ' -f 2)
rustup := $(shell command -v rustup 2> /dev/null)

check_cargo:
  ifndef cargo
    $(error cargo is not available, please install it! curl https://sh.rustup.rs -sSf | sh)
  else
	@echo "Make sure your cargo version is up to date! Current version is $(cargo_v)"
  endif

check_rustup:
  ifndef rustup
    $(error rustup is not available, please install it! curl https://sh.rustup.rs -sSf | sh)
  endif

build:
	sudo docker build . -t rust_cross_compile/windows
	sudo docker run -e OBFSTR_SEED='$(shell seq 10 | awk 'BEGIN{srand()}{ORS=""}{print(int(rand()*10))}' | sha512sum | awk '{print $$1}')' -v $(shell pwd):/app rust_cross_compile/windows cargo build --target x86_64-pc-windows-gnu
	cp target/x86_64-pc-windows-gnu/debug/*.exe .

release:
	sudo docker build . -t rust_cross_compile/windows
	sudo docker run -e OBFSTR_SEED='$(shell seq 10 | awk 'BEGIN{srand()}{ORS=""}{print(int(rand()*10))}' | sha512sum | awk '{print $$1}')' -v $(shell pwd):/app rust_cross_compile/windows cargo build --release -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-pc-windows-gnu
	cp target/x86_64-pc-windows-gnu/release/*.exe .

clean:
	sudo rm -rf ./target

install_windows_deps:
	@rustup install stable-x86_64-pc-windows-gnu --force-non-host
	@rustup target add x86_64-pc-windows-gnu

build_windows:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-pc-windows-gnu
	@echo "[+] You can find $(prog).exe in target/x86_64-pc-windows-gnu/release folder."

windows: check_rustup install_windows_deps build_windows

help:
	@echo ""
	@echo "From docker:"
	@echo "usage: make debug"
	@echo "usage: make release"
	@echo ""
	@echo "From cargo:"
	@echo "usage: make windows"
	@echo ""
	@echo "Dependencies:"
	@echo "usage: make install_windows_deps"
	@echo ""