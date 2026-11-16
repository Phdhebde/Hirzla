#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use super::{read_database as read, KdbxDatabase, KdbxEntry, KdbxRefusal};
use crate::VaultError;

const PASSWORD: &str = "hirzla-test";

const PYKEEPASS_AES_ARGON2D: &[u8] = include_bytes!("../../tests/kdbx/pykeepass-aes-argon2d.kdbx");
const PYKEEPASS_CHACHA20_ARGON2ID: &[u8] =
    include_bytes!("../../tests/kdbx/pykeepass-chacha20-argon2id.kdbx");
const PYKEEPASS_AES_ARGON2ID_PLAIN: &[u8] =
    include_bytes!("../../tests/kdbx/pykeepass-aes-argon2id-plain.kdbx");
const PYKEEPASS_CHACHA20_ARGON2D_PLAIN: &[u8] =
    include_bytes!("../../tests/kdbx/pykeepass-chacha20-argon2d-plain.kdbx");
const KEEPASSXC_AES_ARGON2D: &[u8] = include_bytes!("../../tests/kdbx/keepassxc-aes-argon2d.kdbx");
const KEEPASSXC_CHACHA20_ARGON2ID: &[u8] =
    include_bytes!("../../tests/kdbx/keepassxc-chacha20-argon2id.kdbx");
const KEEPASSXC_KDBX3_AESKDF: &[u8] =
    include_bytes!("../../tests/kdbx/keepassxc-kdbx3-aeskdf.kdbx");

/// Name, file, and whether its recycle bin is marked as such. A KeePassXC merge copies the
/// groups but not the database metadata: there the « Corbeille » group is an ordinary group.
const READABLE: [(&str, &[u8], bool); 6] = [
    ("pykeepass-aes-argon2d", PYKEEPASS_AES_ARGON2D, true),
    (
        "pykeepass-chacha20-argon2id",
        PYKEEPASS_CHACHA20_ARGON2ID,
        true,
    ),
    (
        "pykeepass-aes-argon2id-plain",
        PYKEEPASS_AES_ARGON2ID_PLAIN,
        true,
    ),
    (
        "pykeepass-chacha20-argon2d-plain",
        PYKEEPASS_CHACHA20_ARGON2D_PLAIN,
        true,
    ),
    ("keepassxc-aes-argon2d", KEEPASSXC_AES_ARGON2D, false),
    (
        "keepassxc-chacha20-argon2id",
        KEEPASSXC_CHACHA20_ARGON2ID,
        false,
    ),
];

fn s(v: &Option<zeroize::Zeroizing<String>>) -> Option<&str> {
    v.as_ref().map(|z| z.as_str())
}

fn strs(v: &[zeroize::Zeroizing<String>]) -> Vec<&str> {
    v.iter().map(|z| z.as_str()).collect()
}

fn find<'a>(db: &'a KdbxDatabase, title: Option<&str>) -> &'a KdbxEntry {
    db.entries
        .iter()
        .find(|e| s(&e.title) == title)
        .unwrap_or_else(|| panic!("missing entry {title:?}"))
}

fn check_content(name: &str, db: &KdbxDatabase, recycle_marked: bool) {
    if recycle_marked {
        assert_eq!(db.entries.len(), 5, "{name}");
        assert_eq!(db.recycled, 1, "{name}");
        assert!(
            db.entries.iter().all(|e| s(&e.title) != Some("Supprimé")),
            "{name}"
        );
    } else {
        assert_eq!(db.entries.len(), 6, "{name}");
        assert_eq!(db.recycled, 0, "{name}");
        let gone = find(db, Some("Supprimé"));
        assert_eq!(strs(&gone.group_path), ["Corbeille"], "{name}");
    }

    let untitled = find(db, None);
    assert_eq!(
        s(&untitled.url),
        Some("https://sans-titre.example"),
        "{name}"
    );
    assert_eq!(s(&untitled.password), Some("x"), "{name}");
    assert!(untitled.group_path.is_empty(), "{name}");

    let note = find(db, Some("Note seule"));
    assert_eq!(s(&note.notes), Some("Rien d'autre"), "{name}");
    assert_eq!(note.password, None, "{name}");

    let empty = find(db, Some("Vide"));
    assert_eq!(empty.password, None, "{name}");
    assert_eq!(empty.username, None, "{name}");
    assert_eq!(empty.notes, None, "{name}");

    let mail = find(db, Some("Messagerie"));
    assert_eq!(s(&mail.username), Some("alice@example.org"), "{name}");
    assert_eq!(
        s(&mail.password),
        Some("mot-de-passe-très-secret"),
        "{name}"
    );
    assert_eq!(s(&mail.url), Some("https://mail.example.org"), "{name}");
    assert_eq!(
        s(&mail.notes),
        Some("Ligne 1\nLigne 2 & <spécial>"),
        "{name}"
    );
    let mut tags = strs(&mail.tags);
    tags.sort_unstable();
    assert_eq!(tags, ["mail", "perso"], "{name}");
    assert_eq!(strs(&mail.group_path), ["Internet", "Mail"], "{name}");
    assert!(mail.totp, "{name}");
    assert_eq!(mail.history, 1, "{name}");
    assert_eq!(mail.attachments, 0, "{name}");
    assert_eq!(mail.custom_skipped, 0, "{name}");
    let mut custom: Vec<(&str, &str, bool)> = mail
        .custom
        .iter()
        .map(|f| (f.label.as_str(), f.value.as_str(), f.protected))
        .collect();
    custom.sort_unstable();
    assert_eq!(
        custom,
        [
            ("Numéro client", "12345", false),
            ("Question secrète", "Nom du chat", true)
        ],
        "{name}"
    );

    let bank = find(db, Some("Banque"));
    assert_eq!(s(&bank.username), Some("bob"), "{name}");
    assert_eq!(s(&bank.password), Some("Pa55w0rd!"), "{name}");
    assert_eq!(bank.attachments, 1, "{name}");
    assert_eq!(strs(&bank.group_path), ["Banque"], "{name}");
    assert!(!bank.totp, "{name}");
}

#[test]
fn reads_reference_databases() {
    for (name, file, recycle_marked) in READABLE {
        let db = read(file, PASSWORD).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        check_content(name, &db, recycle_marked);
    }
}

#[test]
fn wrong_password_is_rejected() {
    for (name, file, _) in READABLE {
        assert_eq!(
            read(file, "hirzla-test ").err(),
            Some(KdbxRefusal::WrongKey),
            "{name}"
        );
    }
}

#[test]
fn kdbx3_is_unsupported() {
    assert_eq!(
        read(KEEPASSXC_KDBX3_AESKDF, PASSWORD).err(),
        Some(KdbxRefusal::Unsupported)
    );
    // The public entry point carries the reason in the crate's error type.
    assert_eq!(
        super::read(KEEPASSXC_KDBX3_AESKDF, PASSWORD).err(),
        Some(VaultError::Kdbx(KdbxRefusal::Unsupported))
    );
}

#[test]
fn not_kdbx() {
    assert_eq!(read(b"", PASSWORD).err(), Some(KdbxRefusal::NotKdbx));
    assert_eq!(
        read(b"<?xml version=\"1.0\"?><KeePassFile/>", PASSWORD).err(),
        Some(KdbxRefusal::NotKdbx)
    );
    for len in [4, 8, 10] {
        assert_eq!(
            read(&PYKEEPASS_AES_ARGON2D[..len], PASSWORD).err(),
            Some(KdbxRefusal::NotKdbx),
            "{len}"
        );
    }
    // A KeePass signature, then truncated inside the header or its hash.
    let end = header_end(PYKEEPASS_AES_ARGON2D);
    for len in [12, 40, 100, end, end + 20, end + 40] {
        assert_eq!(
            read(&PYKEEPASS_AES_ARGON2D[..len], PASSWORD).err(),
            Some(KdbxRefusal::Malformed),
            "{len}"
        );
    }
}

/// Offset of the end of the outer header (its SHA-256 follows).
fn header_end(file: &[u8]) -> usize {
    let mut pos = 12;
    loop {
        let id = file[pos];
        let len = u32::from_le_bytes(file[pos + 1..pos + 5].try_into().unwrap()) as usize;
        pos += 5 + len;
        if id == 0 {
            return pos;
        }
    }
}

#[test]
fn altered_header_is_rejected() {
    let end = header_end(PYKEEPASS_AES_ARGON2D);
    // A flipped byte in the master seed: the hash no longer matches.
    let mut file = PYKEEPASS_AES_ARGON2D.to_vec();
    file[end - 10] ^= 1;
    assert_eq!(read(&file, PASSWORD).err(), Some(KdbxRefusal::Malformed));
    // A flipped byte in the stored hash.
    let mut file = PYKEEPASS_AES_ARGON2D.to_vec();
    file[end + 3] ^= 1;
    assert_eq!(read(&file, PASSWORD).err(), Some(KdbxRefusal::Malformed));
    // A flipped byte in the header HMAC: indistinguishable from a wrong password.
    let mut file = PYKEEPASS_AES_ARGON2D.to_vec();
    file[end + 32 + 3] ^= 1;
    assert_eq!(read(&file, PASSWORD).err(), Some(KdbxRefusal::WrongKey));
}

#[test]
fn altered_blocks_are_rejected() {
    let end = header_end(PYKEEPASS_CHACHA20_ARGON2D_PLAIN) + 64;
    let len = PYKEEPASS_CHACHA20_ARGON2D_PLAIN.len();
    // Block HMAC, block size, block data, final empty block.
    for pos in [end + 1, end + 33, end + 40, end + 1000, len - 1] {
        let mut file = PYKEEPASS_CHACHA20_ARGON2D_PLAIN.to_vec();
        file[pos] ^= 0x40;
        assert!(
            matches!(
                read(&file, PASSWORD).err(),
                Some(KdbxRefusal::Malformed | KdbxRefusal::TooLarge)
            ),
            "{pos}"
        );
    }
    // Truncated: the final empty block is missing.
    let file = &PYKEEPASS_CHACHA20_ARGON2D_PLAIN[..len - 40];
    assert_eq!(read(file, PASSWORD).err(), Some(KdbxRefusal::Malformed));
}

#[test]
fn oversized_file_is_refused() {
    let file = vec![0u8; super::MAX_FILE + 1];
    assert_eq!(read(&file, PASSWORD).err(), Some(KdbxRefusal::TooLarge));
}

fn parse_xml(doc: &str) -> Result<KdbxDatabase, KdbxRefusal> {
    let mut stream = hirzla_crypto::kdbx::InnerStream::new(&[7u8; 64]).unwrap();
    super::xml::parse(doc.as_bytes(), &mut stream)
}

const MINIMAL: &str = "<KeePassFile><Root><Group><Name>R</Name>\
    <Group><Name>A</Name><Entry><String><Key>Title</Key><Value>T &#233;&amp;</Value></String>\
    </Entry></Group></Group></Root></KeePassFile>";

#[test]
fn xml_minimal_document() {
    let db = parse_xml(MINIMAL).unwrap();
    assert_eq!(db.entries.len(), 1);
    assert_eq!(s(&db.entries[0].title), Some("T é&"));
    assert_eq!(strs(&db.entries[0].group_path), ["A"]);
    // With a byte order mark.
    let db = parse_xml(&format!("\u{feff}{MINIMAL}")).unwrap();
    assert_eq!(db.entries.len(), 1);
}

#[test]
fn xml_refusals() {
    let doctype = format!("<?xml version=\"1.0\"?><!DOCTYPE k [<!ENTITY x \"y\">]>{MINIMAL}");
    for doc in [
        doctype.as_str(),
        "<KeePassFile><Root><Group><Name>&x;</Name></Group></Root></KeePassFile>",
        "<KeePassFile><Root></Group></Root></KeePassFile>",
        "<KeePassFile><Root>",
        "<Other/>",
        "<KeePassFile/><KeePassFile/>",
        "<KeePassFile/>trailing",
        "<KeePassFile><Root><Group><Entry><String><Key>Password</Key>\
         <Value Protected=\"True\">not base64!</Value></String></Entry></Group></Root></KeePassFile>",
    ] {
        assert_eq!(parse_xml(doc).err(), Some(KdbxRefusal::Malformed), "{doc}");
    }
}

#[test]
fn xml_depth_is_bounded() {
    let depth = 129;
    let doc = format!(
        "<KeePassFile>{}{}</KeePassFile>",
        "<a>".repeat(depth),
        "</a>".repeat(depth)
    );
    assert_eq!(parse_xml(&doc).err(), Some(KdbxRefusal::TooLarge));
}

#[test]
fn xml_custom_fields_are_bounded() {
    let mut doc = String::from("<KeePassFile><Root><Group><Entry>");
    for i in 0..67 {
        doc.push_str(&format!("<String><Key>k{i}</Key><Value>v</Value></String>"));
    }
    doc.push_str("<String><Key>TimeOtp-Secret-Base32</Key><Value>AAAA</Value></String>");
    doc.push_str("</Entry></Group></Root></KeePassFile>");
    let db = parse_xml(&doc).unwrap();
    let e = &db.entries[0];
    assert_eq!(e.custom.len(), 64);
    assert_eq!(e.custom_skipped, 3);
    assert!(e.totp);
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

    /// The stages after decryption never panic, whatever the payload.
    #[test]
    fn payload_never_panics(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048), gzip: bool) {
        let _ = super::read_payload(zeroize::Zeroizing::new(data), gzip);
    }

    /// Nor does the reader on a reference database with one byte changed.
    #[test]
    fn altered_file_never_panics(pos in 0usize..2069, bit in 0u8..8) {
        let mut file = PYKEEPASS_AES_ARGON2D.to_vec();
        file[pos] ^= 1 << bit;
        proptest::prop_assert!(read(&file, PASSWORD).is_err());
    }
}
