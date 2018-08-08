fn main() {
	let target    = std::env::var("TARGET").expect("TARGET couldn't be decoded.");
	let directory = std::env::var("CARGO_MANIFEST_DIR").expect("TARGET couldn't be decoded.");

	match target.as_ref() {
		"x86_64-pc-windows-gnu" | "x86_64-pc-windows-msvc" => {
			println!("cargo:rustc-link-lib=dylib=ntdll");
			println!("cargo:rustc-link-search=native={}\\lib\\x64", directory);
		},

		"i686-pc-windows-gnu" | "i686-pc-windows-msvc" => {
			println!("cargo:rustc-link-lib=dylib=ntdll");
			println!("cargo:rustc-link-search=native={}\\lib\\x86", directory);
		},

		_ => { },
	}
}
