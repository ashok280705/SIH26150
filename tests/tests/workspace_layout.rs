//! Workspace layout assertion test (P1-001).
//!
//! Guards the structural contract from design.md → "Workspace Layout", "System Topology",
//! and "OEM Profile Directory":
//!
//! * every forensic core crate and all five currently supported per-OEM parser crates exist
//!   and are workspace members, Uniview included as a first-class crate (Req 6.3, 6.4, 25.1);
//! * OEM knowledge lives in `profiles/` data directories, not source (Req 6.1, 6.2);
//! * future OEM directories are present but explicitly NOT implemented;
//! * `apps/api` is the only crate permitted network/database dependencies;
//! * `cases/` is git-ignored so evidence is never committed.
//!
//! **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 25.1**

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Forensic core crates under `crates/`. Directory name == package name.
const CORE_CRATES: &[&str] = &[
    "forensic-core",
    "evidence-reader",
    "hashing",
    "detection",
    "confidence",
    "recovery",
    "timeline",
    "reporting",
];

/// The five currently supported OEMs: `crates/parsers/<dir>` -> package name.
const SUPPORTED_OEM_PARSERS: &[(&str, &str)] = &[
    ("dahua", "parser-dahua"),
    ("hikvision", "parser-hikvision"),
    ("honeywell", "parser-honeywell"),
    ("cpplus-ubs", "parser-cpplus-ubs"),
    ("uniview", "parser-uniview"),
];

/// Profile data directories for the currently supported OEMs.
const SUPPORTED_PROFILE_DIRS: &[&str] =
    &["dahua", "hikvision", "honeywell", "cpplus", "uniview"];

/// Future OEMs: directories exist as extension points but are NOT implemented.
const FUTURE_PROFILE_DIRS: &[&str] = &["tplink", "godrej", "matrix"];

/// Support directories required by the design layout.
const SUPPORT_DIRS: &[&str] = &[
    "profiles",
    "services/ai",
    "validation_corpus",
    "tests",
    "docs",
];

/// Network and database dependencies that only `apps/api` may declare. Async runtimes
/// (Tokio, Rayon) are deliberately absent: the core uses them for bounded parallelism and
/// cancellation, not for I/O to the outside world.
const NETWORK_AND_DB_DEPS: &[&str] = &[
    "axum",
    "actix-web",
    "warp",
    "rocket",
    "hyper",
    "reqwest",
    "tonic",
    "ureq",
    "sqlx",
    "diesel",
    "sea-orm",
    "tokio-postgres",
    "postgres",
    "deadpool-postgres",
    "mongodb",
    "redis",
    "r2d2",
    "bb8",
];

/// Repository root: the parent of this crate's manifest directory (`<root>/tests`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the forensic-tests crate must live directly under the workspace root")
        .to_path_buf()
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Assert that `<root>/<rel>` is a crate directory declaring package `package`.
fn assert_crate_at(rel: &str, package: &str) {
    let dir = repo_root().join(rel);
    assert!(dir.is_dir(), "missing crate directory: {rel}");

    let manifest_path = dir.join("Cargo.toml");
    assert!(manifest_path.is_file(), "missing manifest: {rel}/Cargo.toml");

    let manifest = read_to_string(&manifest_path);
    assert!(
        manifest.contains(&format!("name = \"{package}\"")),
        "{rel}/Cargo.toml must declare package name \"{package}\""
    );

    let has_lib = dir.join("src/lib.rs").is_file();
    let has_main = dir.join("src/main.rs").is_file();
    assert!(
        has_lib || has_main,
        "{rel} must have a crate root at src/lib.rs or src/main.rs"
    );
}

/// Collect declared dependency names from a Cargo.toml. Text-scanned so this test needs no
/// dependencies of its own. Handles `[dependencies]`, `[dev-dependencies]`,
/// `[build-dependencies]`, and `[dependencies.<name>]` table forms.
fn declared_dependencies(manifest: &str) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let mut in_dependency_table = false;

    for raw_line in manifest.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') {
            let header = line
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or_default();
            let segments: Vec<&str> = header.split('.').collect();

            // `[dependencies.<name>]` declares a single dependency in table form.
            if segments.len() >= 2 && segments[segments.len() - 2].ends_with("dependencies") {
                deps.insert(segments[segments.len() - 1].trim_matches('"').to_string());
                in_dependency_table = false;
                continue;
            }

            in_dependency_table = segments
                .last()
                .is_some_and(|segment| segment.ends_with("dependencies"));
            continue;
        }

        if in_dependency_table {
            if let Some((key, _)) = line.split_once('=') {
                deps.insert(key.trim().trim_matches('"').to_string());
            }
        }
    }

    deps
}

/// Every crate that must stay pure: forensic core plus the per-OEM parsers.
fn pure_crate_dirs() -> Vec<String> {
    let mut dirs: Vec<String> = CORE_CRATES
        .iter()
        .map(|name| format!("crates/{name}"))
        .collect();
    dirs.extend(
        SUPPORTED_OEM_PARSERS
            .iter()
            .map(|(dir, _)| format!("crates/parsers/{dir}")),
    );
    dirs
}

#[test]
fn workspace_root_is_a_cargo_workspace() {
    let manifest_path = repo_root().join("Cargo.toml");
    assert!(
        manifest_path.is_file(),
        "workspace root Cargo.toml is missing"
    );

    let manifest = read_to_string(&manifest_path);
    assert!(
        manifest.contains("[workspace]"),
        "root Cargo.toml must declare a [workspace]"
    );
}

#[test]
fn forensic_core_crate_skeletons_exist() {
    for name in CORE_CRATES {
        assert_crate_at(&format!("crates/{name}"), name);
    }
}

#[test]
fn all_five_supported_oem_parser_crates_exist_including_uniview() {
    for (dir, package) in SUPPORTED_OEM_PARSERS {
        assert_crate_at(&format!("crates/parsers/{dir}"), package);
    }

    // Uniview is a first-class supported OEM, not future work (Req 25.1).
    assert!(
        SUPPORTED_OEM_PARSERS.iter().any(|(dir, _)| *dir == "uniview"),
        "uniview must be one of the currently supported OEM parser crates"
    );

    // `crates/parsers` groups the OEM crates; it is not itself a crate.
    assert!(
        !repo_root().join("crates/parsers/Cargo.toml").exists(),
        "crates/parsers is a grouping directory and must not be a crate"
    );
}

#[test]
fn every_crate_directory_is_a_declared_workspace_member() {
    let manifest = read_to_string(&repo_root().join("Cargo.toml"));

    let mut expected_members = pure_crate_dirs();
    expected_members.push("apps/api".to_string());
    expected_members.push("tests".to_string());

    for member in expected_members {
        assert!(
            manifest.contains(&format!("\"{member}\"")),
            "root Cargo.toml must list \"{member}\" as a workspace member"
        );
    }
}

#[test]
fn apps_api_is_a_binary_crate_and_frontend_is_a_directory() {
    assert_crate_at("apps/api", "forensic-api");
    assert!(
        repo_root().join("apps/api/src/main.rs").is_file(),
        "apps/api must be a binary crate with src/main.rs"
    );

    // The frontend is a sibling app, not a Cargo member. There is no Node.js backend.
    let frontend = repo_root().join("apps/frontend");
    assert!(frontend.is_dir(), "missing apps/frontend directory");
    assert!(
        !frontend.join("Cargo.toml").exists(),
        "apps/frontend is a TypeScript app and must not be a Cargo crate"
    );
}

#[test]
fn support_directories_exist() {
    for dir in SUPPORT_DIRS {
        assert!(
            repo_root().join(dir).is_dir(),
            "missing required directory: {dir}"
        );
    }
}

#[test]
fn supported_oem_profile_directories_exist_including_uniview() {
    for oem in SUPPORTED_PROFILE_DIRS {
        let dir = repo_root().join("profiles").join(oem);
        assert!(dir.is_dir(), "missing profile directory: profiles/{oem}");
    }

    // Every supported parser crate has a matching profile directory, so OEM knowledge is
    // data rather than source (Req 6.1).
    assert_eq!(
        SUPPORTED_PROFILE_DIRS.len(),
        SUPPORTED_OEM_PARSERS.len(),
        "each supported OEM parser crate needs exactly one profile directory"
    );
}

#[test]
fn future_oem_profile_directories_are_present_but_not_implemented() {
    for oem in FUTURE_PROFILE_DIRS {
        let dir = repo_root().join("profiles").join(oem);
        assert!(
            dir.is_dir(),
            "missing future OEM placeholder directory: profiles/{oem}"
        );

        let marker = dir.join("NOT_IMPLEMENTED.md");
        assert!(
            marker.is_file(),
            "profiles/{oem} must carry a NOT_IMPLEMENTED.md marker so it is never read as supported"
        );
        assert!(
            read_to_string(&marker).contains("NOT implemented"),
            "profiles/{oem}/NOT_IMPLEMENTED.md must state that the OEM is NOT implemented"
        );

        // A placeholder holds no profile data: nothing can load or claim support for it.
        let profile_files: Vec<_> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot list profiles/{oem}: {e}"))
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
            })
            .collect();
        assert!(
            profile_files.is_empty(),
            "profiles/{oem} must contain no profile data while unimplemented"
        );

        // No detector/parser crate may exist for an unimplemented OEM.
        assert!(
            !repo_root().join("crates/parsers").join(oem).exists(),
            "profiles/{oem} is a placeholder, so crates/parsers/{oem} must not exist"
        );
    }
}

#[test]
fn cases_directory_is_git_ignored_so_evidence_is_never_committed() {
    let gitignore_path = repo_root().join(".gitignore");
    assert!(gitignore_path.is_file(), "missing .gitignore at repo root");

    let gitignore = read_to_string(&gitignore_path);
    let ignored: BTreeSet<&str> = gitignore
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    assert!(
        ignored.contains("cases/"),
        ".gitignore must exclude `cases/` so evidence is never committed"
    );
}

#[test]
fn core_and_parser_crates_declare_no_network_or_database_dependencies() {
    for crate_dir in pure_crate_dirs() {
        let manifest = read_to_string(&repo_root().join(&crate_dir).join("Cargo.toml"));
        let deps = declared_dependencies(&manifest);

        for forbidden in NETWORK_AND_DB_DEPS {
            assert!(
                !deps.contains(*forbidden),
                "{crate_dir} declares `{forbidden}`: only apps/api may touch the network or the database"
            );
        }
    }
}

/// Unit tests for the dependency extractor itself, so the network/database guard above is
/// provably non-vacuous rather than passing because it detects nothing.
mod dependency_extraction {
    use super::{declared_dependencies, NETWORK_AND_DB_DEPS};

    #[test]
    fn extracts_inline_dependencies() {
        let deps = declared_dependencies(
            "[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"\naxum = { version = \"0.7\" }\n",
        );
        assert!(deps.contains("serde"));
        assert!(deps.contains("axum"));
        assert!(!deps.contains("name"), "package keys are not dependencies");
    }

    #[test]
    fn extracts_table_form_and_dev_and_build_dependencies() {
        let deps = declared_dependencies(
            "[dependencies.sqlx]\nversion = \"0.7\"\n\n[dev-dependencies]\nproptest = \"1\"\n\n[build-dependencies]\ncc = \"1\"\n",
        );
        assert!(deps.contains("sqlx"), "[dependencies.<name>] form must be detected");
        assert!(deps.contains("proptest"));
        assert!(deps.contains("cc"));
        assert!(
            !deps.contains("version"),
            "keys inside a [dependencies.<name>] table are not dependency names"
        );
    }

    #[test]
    fn ignores_comments_and_non_dependency_tables() {
        let deps = declared_dependencies(
            "[package]\nname = \"x\"\ndescription = \"y\"\n\n# axum = \"0.7\"\n[dependencies]\n",
        );
        assert!(deps.is_empty(), "found unexpected dependencies: {deps:?}");
    }

    #[test]
    fn forbidden_dependency_in_a_pure_crate_is_detected() {
        let deps = declared_dependencies("[dependencies]\naxum = \"0.7\"\ntokio = \"1\"\n");
        let violations: Vec<&&str> = NETWORK_AND_DB_DEPS
            .iter()
            .filter(|forbidden| deps.contains(**forbidden))
            .collect();
        assert_eq!(
            violations,
            vec![&"axum"],
            "axum must be flagged; tokio is an allowed runtime, not a network/DB dependency"
        );
    }
}
