// build.rs

fn main() {
  cc::Build::new()
      .file("../../re.c")
      .compile("re");
  println!("cargo::rerun-if-changed=../../re.c");
}
