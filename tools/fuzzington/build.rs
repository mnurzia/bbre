// build.rs

fn main() {
  cc::Build::new()
      .file("../../bbre.c")
      .compile("bbre");
  println!("cargo::rerun-if-changed=../../bbre.c");
}
