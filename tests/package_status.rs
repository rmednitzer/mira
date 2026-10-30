use mira::packages;
use std::path::Path;

#[test]
fn parses_synthetic_dpkg_database() {
    let file = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dpkg/status"
    ));
    let packages = packages::collect(file).expect("synthetic fixture parses");
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "alpha");
    assert_eq!(packages[0].architecture, "amd64");
    assert_eq!(packages[0].version, "1.2-3ubuntu1");
}
