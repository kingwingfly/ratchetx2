//! The languages code previews highlight, and which worker highlights each: the grammars of them
//! all would make one file larger than Cloudflare serves (25 MiB), so four workers share them,
//! each with languages written together, as HTML is with JavaScript and CSS, whose grammars it
//! embeds.

/// The languages a worker highlights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    /// The web's languages, its data formats, and SQL.
    Web,
    /// Systems languages, the shell, and build and configuration files.
    Systems,
    /// The JVM's, .NET's, and mobile apps' languages.
    Apps,
    /// Scripting and functional languages.
    Scripts,
}

impl Group {
    pub const ALL: [Self; 4] = [Self::Web, Self::Systems, Self::Apps, Self::Scripts];
}

/// A language code previews highlight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Language {
    /// Its name, as its grammar is registered under.
    pub name: &'static str,
    pub group: Group,
    /// File extensions, in lower case.
    pub extensions: &'static [&'static str],
    /// Whole file names, in lower case, e.g. `makefile`.
    pub files: &'static [&'static str],
    /// What else code blocks call it, in lower case.
    pub aliases: &'static [&'static str],
}

const fn language(
    name: &'static str,
    group: Group,
    extensions: &'static [&'static str],
    files: &'static [&'static str],
    aliases: &'static [&'static str],
) -> Language {
    Language {
        name,
        group,
        extensions,
        files,
        aliases,
    }
}

use Group::*;

// One language a line, as a table.
#[rustfmt::skip]
pub const LANGUAGES: &[Language] = &[
    // The web.
    language("javascript", Web, &["js", "mjs", "cjs", "jsx"], &[], &["node"]),
    language("typescript", Web, &["ts", "mts", "cts"], &[], &[]),
    language("tsx", Web, &["tsx"], &[], &[]),
    language("json", Web, &["json", "jsonc", "json5", "ipynb", "webmanifest", "geojson"], &[], &[]),
    language("html", Web, &["html", "htm", "xhtml"], &[], &[]),
    language("css", Web, &["css"], &[], &[]),
    language("scss", Web, &["scss"], &[], &[]),
    language("vue", Web, &["vue"], &[], &[]),
    language("xml", Web, &["xml", "svg", "xsl", "xslt", "xsd", "plist", "rss", "atom", "kml", "gpx"], &[], &[]),
    language("markdown", Web, &["md", "markdown"], &[], &[]),
    language("yaml", Web, &["yaml", "yml"], &[], &[]),
    language("toml", Web, &["toml"], &["cargo.lock", "poetry.lock", "uv.lock", "pipfile"], &[]),
    language("php", Web, &["php", "phtml"], &[], &[]),
    language("sql", Web, &["sql"], &[], &["postgresql", "postgres", "mysql", "sqlite"]),
    // Systems.
    language("rust", Systems, &["rs"], &[], &[]),
    language("c", Systems, &["c", "h"], &[], &[]),
    language("cpp", Systems, &["cpp", "cc", "cxx", "c++", "hpp", "hh", "hxx", "h++", "ino"], &[], &[]),
    language("go", Systems, &["go"], &[], &["golang"]),
    language("zig", Systems, &["zig", "zon"], &[], &[]),
    language(
        "bash",
        Systems,
        &["sh", "bash", "zsh", "ksh", "ebuild"],
        &[".bashrc", ".bash_profile", ".zshrc", ".profile", "pkgbuild"],
        &["shell", "console", "shellsession", "shell-session"],
    ),
    language("make", Systems, &["mk", "mak"], &["makefile", "gnumakefile"], &[]),
    language("dockerfile", Systems, &["dockerfile"], &["dockerfile", "containerfile"], &["docker"]),
    language("nix", Systems, &["nix"], &[], &[]),
    language("diff", Systems, &["diff", "patch"], &[], &[]),
    language("proto", Systems, &["proto"], &[], &["protobuf"]),
    language("lua", Systems, &["lua"], &[], &[]),
    language("ini", Systems, &["ini", "cfg", "conf", "desktop"], &[".editorconfig", ".gitconfig"], &[]),
    // Apps.
    language("java", Apps, &["java"], &[], &[]),
    language("kotlin", Apps, &["kt", "kts"], &[], &[]),
    language("scala", Apps, &["scala", "sc", "sbt"], &[], &[]),
    language("c-sharp", Apps, &["cs", "csx"], &[], &["c#", "csharp"]),
    language("swift", Apps, &["swift"], &[], &[]),
    language("dart", Apps, &["dart"], &[], &[]),
    // Scripts.
    language("python", Scripts, &["py", "pyw", "pyi"], &[], &["python3"]),
    language("ruby", Scripts, &["rb", "rake", "gemspec"], &["gemfile", "rakefile"], &[]),
    language("elixir", Scripts, &["ex", "exs"], &[], &[]),
    language("haskell", Scripts, &["hs"], &[], &[]),
    language("ocaml", Scripts, &["ml", "mli"], &[], &[]),
    language("julia", Scripts, &["jl"], &[], &[]),
];

/// The language of the file `name`, by its whole name, then its extension.
pub fn of_file(name: &str) -> Option<&'static Language> {
    let lower = name.to_lowercase();
    let file = lower.as_str();
    LANGUAGES
        .iter()
        .find(|language| language.files.contains(&file))
        .or_else(|| {
            let (_, extension) = file.rsplit_once('.')?;
            LANGUAGES
                .iter()
                .find(|language| language.extensions.contains(&extension))
        })
}

/// The language a code block's `info` names: by its name or an alias, then as an extension or
/// a file name, e.g. `rs` or `Makefile`.
pub fn of_block(info: &str) -> Option<&'static Language> {
    let lower = info.trim().to_lowercase();
    let info = lower.as_str();
    LANGUAGES
        .iter()
        .find(|language| language.name == info || language.aliases.contains(&info))
        .or_else(|| {
            LANGUAGES.iter().find(|language| {
                language.extensions.contains(&info) || language.files.contains(&info)
            })
        })
}

/// The language named `name`.
pub fn named(name: &str) -> Option<&'static Language> {
    LANGUAGES.iter().find(|language| language.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files() {
        assert_eq!(of_file("main.rs").map(|l| l.name), Some("rust"));
        assert_eq!(of_file("Makefile").map(|l| l.name), Some("make"));
        assert_eq!(of_file("Cargo.lock").map(|l| l.name), Some("toml"));
        assert_eq!(of_file("App.TSX").map(|l| l.name), Some("tsx"));
        // A name without an extension is no language, though it is an extension's.
        assert_eq!(of_file("go"), None);
        assert_eq!(of_file("notes.txt"), None);
    }

    #[test]
    fn blocks() {
        assert_eq!(of_block("Rust").map(|l| l.name), Some("rust"));
        assert_eq!(of_block("rs").map(|l| l.name), Some("rust"));
        assert_eq!(of_block("c#").map(|l| l.name), Some("c-sharp"));
        assert_eq!(of_block("shell").map(|l| l.name), Some("bash"));
        assert_eq!(of_block("Dockerfile").map(|l| l.name), Some("dockerfile"));
        assert_eq!(of_block("mermaid"), None);
    }

    #[test]
    fn names_are_unique() {
        for (i, language) in LANGUAGES.iter().enumerate() {
            assert!(
                LANGUAGES[..i]
                    .iter()
                    .all(|other| other.name != language.name),
                "{} twice",
                language.name
            );
        }
    }
}
