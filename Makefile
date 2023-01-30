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
