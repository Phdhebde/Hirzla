#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use super::{KdbxDatabase, KdbxEntry, KdbxKey, KdbxRefusal};
use crate::VaultError;

const PASSWORD: &str = "hirzla-test";

fn read(file: &[u8], password: &str) -> Result<KdbxDatabase, KdbxRefusal> {
    super::read_database(
        file,
        KdbxKey {
            password: Some(password),
            key_file: None,
        },
    )
}

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
    let otp: Vec<&str> = mail.otp.iter().map(|f| f.label.as_str()).collect();
    assert_eq!(otp, ["otp"], "{name}");
    assert!(mail.otp[0].value.starts_with("otpauth://totp/"), "{name}");
    assert_eq!(mail.history, 1, "{name}");
    assert!(mail.attachments.is_empty(), "{name}");
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
    assert_eq!(bank.attachments.len(), 1, "{name}");
    assert_eq!(bank.attachments[0].name.as_str(), "releve.txt", "{name}");
    assert_eq!(
        db.binary(bank.attachments[0].reference),
        Some("Relevé de compte\n".as_bytes()),
        "{name}"
    );
    assert_eq!(strs(&bank.group_path), ["Banque"], "{name}");
    assert!(bank.otp.is_empty(), "{name}");
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
fn kdbx3_written_by_keepassxc() {
    // KeePassXC 2.7.6 import of source.xml: KDBX 3.1, AES-KDF (100 rounds), Salsa20 stream.
    let db = read(KEEPASSXC_KDBX3_AESKDF, PASSWORD).unwrap();
    check_content("keepassxc-kdbx3-aeskdf", &db, true);
    assert_eq!(
        read(KEEPASSXC_KDBX3_AESKDF, "hirzla-test ").err(),
        Some(KdbxRefusal::WrongKey)
    );
    // The public entry point carries the reason in the crate's error type.
    assert_eq!(
        super::read(KEEPASSXC_KDBX3_AESKDF, "x").err(),
        Some(VaultError::Kdbx(KdbxRefusal::WrongKey))
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
    assert_eq!(e.otp.len(), 1);
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

const PYKEEPASS_KDBX3_AESKDF: &[u8] =
    include_bytes!("../../tests/kdbx/pykeepass-kdbx3-aeskdf.kdbx");
const PYKEEPASS_KDBX4_AESKDF: &[u8] =
    include_bytes!("../../tests/kdbx/pykeepass-kdbx4-aeskdf.kdbx");
const PYKEEPASS_KEYFILE: &[u8] = include_bytes!("../../tests/kdbx/pykeepass-keyfile.kdbx");
const PYKEEPASS_KEYFILE_ONLY: &[u8] =
    include_bytes!("../../tests/kdbx/pykeepass-keyfile-only.kdbx");
const KEYFILE_V2: &[u8] = include_bytes!("../../tests/kdbx/keyfile-v2.keyx");
const KEYFILE_RAW: &[u8] = include_bytes!("../../tests/kdbx/keyfile-raw.bin");

/// The content of `generate_keepass2.py`, as the reader gives it (before any mapping).
fn check_keepass2(name: &str, db: &KdbxDatabase) {
    assert_eq!(db.entries.len(), 14, "{name}");
    let mail = find(db, Some("Messagerie"));
    assert_eq!(
        mail.uuid,
        Some([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef
        ]),
        "{name}"
    );
    let forum = find(db, Some("Forum"));
    assert_eq!(s(&forum.username), Some("alice"), "{name}");
    assert_eq!(s(&forum.url), Some("https://forum.example.org"), "{name}");
    assert_eq!(forum.password, None, "{name}");
    assert_eq!(strs(&forum.group_path), ["Internet"], "{name}");
    let spaces = find(db, Some("Espaces"));
    assert_eq!(s(&spaces.username), Some("   "), "{name}");
    let prot = find(db, Some("Protégé"));
    assert_eq!(s(&prot.username), Some("utilisateur-protégé"), "{name}");
    let r = find(db, Some("Référence"));
    assert_eq!(
        s(&r.username),
        Some("{REF:U@I:0123456789ABCDEF0123456789ABCDEF}"),
        "{name}"
    );
    let exp = find(db, Some("Expire"));
    assert_eq!(
        exp.expiry.as_deref(),
        Some("2027-03-01T12:30:00Z"),
        "{name}"
    );
    assert!(!exp.auto_type.is_default(), "{name}");
    assert_eq!(
        exp.auto_type.sequence.as_deref().map(|z| z.as_str()),
        Some("{USERNAME}{TAB}{PASSWORD}{ENTER}"),
        "{name}"
    );
    assert_eq!(exp.auto_type.associations.len(), 1, "{name}");
    assert_eq!(
        exp.auto_type.associations[0].0.as_str(),
        "Connexion - Navigateur",
        "{name}"
    );
    assert!(mail.auto_type.is_default(), "{name}");
    assert_eq!(mail.expiry, None, "{name}");
    let t = find(db, Some("TOTP KeePass"));
    let mut otp: Vec<&str> = t.otp.iter().map(|f| f.label.as_str()).collect();
    otp.sort_unstable();
    assert_eq!(
        otp,
        [
            "TimeOtp-Algorithm",
            "TimeOtp-Length",
            "TimeOtp-Period",
            "TimeOtp-Secret-Base64"
        ],
        "{name}"
    );
    assert!(t.custom.is_empty(), "{name}");
    let h = find(db, Some("HOTP"));
    assert_eq!(h.custom.len(), 2, "{name}");
    assert!(h.otp.is_empty(), "{name}");
    let contract = find(db, Some("Contrat"));
    let names: Vec<&str> = contract
        .attachments
        .iter()
        .map(|a| a.name.as_str())
        .collect();
    assert_eq!(names, ["contrat.pdf", "donnees.bin"], "{name}");
    assert_eq!(
        db.binary(contract.attachments[0].reference),
        Some(b"contenu partage\n".as_slice()),
        "{name}"
    );
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(
        db.binary(contract.attachments[1].reference),
        Some(all.as_slice()),
        "{name}"
    );
    let copy = find(db, Some("Copie"));
    assert_eq!(
        copy.attachments[0].reference, contract.attachments[0].reference,
        "{name}"
    );
    let deep = find(db, Some("Profond"));
    assert_eq!(deep.group_path.len(), 6, "{name}");
}

#[test]
fn reads_keepass2_style_databases() {
    for (name, file) in [
        ("pykeepass-kdbx3-aeskdf", PYKEEPASS_KDBX3_AESKDF),
        ("pykeepass-kdbx4-aeskdf", PYKEEPASS_KDBX4_AESKDF),
    ] {
        let db = read(file, PASSWORD).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        check_keepass2(name, &db);
        assert_eq!(
            read(file, "hirzla-tesT").err(),
            Some(KdbxRefusal::WrongKey),
            "{name}"
        );
    }
}

fn read_key(
    file: &[u8],
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<KdbxDatabase, KdbxRefusal> {
    super::read_database(file, KdbxKey { password, key_file })
}

#[test]
fn key_files() {
    let db = read_key(PYKEEPASS_KEYFILE, Some(PASSWORD), Some(KEYFILE_V2)).unwrap();
    assert_eq!(s(&db.entries[0].username), Some("kim"));
    let db = read_key(PYKEEPASS_KEYFILE_ONLY, None, Some(KEYFILE_RAW)).unwrap();
    assert_eq!(s(&db.entries[0].username), Some("lou"));
    // A missing or wrong component.
    for (file, password, key_file) in [
        (PYKEEPASS_KEYFILE, Some(PASSWORD), None),
        (PYKEEPASS_KEYFILE, None, Some(KEYFILE_V2)),
        (PYKEEPASS_KEYFILE, Some(PASSWORD), Some(KEYFILE_RAW)),
        (PYKEEPASS_KEYFILE_ONLY, Some(PASSWORD), Some(KEYFILE_RAW)),
        (PYKEEPASS_KEYFILE_ONLY, Some(""), None),
        (PYKEEPASS_AES_ARGON2D, Some(PASSWORD), Some(KEYFILE_RAW)),
    ] {
        assert_eq!(
            read_key(file, password, key_file).err(),
            Some(KdbxRefusal::WrongKey)
        );
    }
    assert_eq!(
        read_key(PYKEEPASS_KEYFILE, None, None).err(),
        Some(KdbxRefusal::WrongKey)
    );
    // A key file that claims to be XML and does not decode.
    assert_eq!(
        read_key(
            PYKEEPASS_KEYFILE,
            Some(PASSWORD),
            Some(
                b"<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data>zz</Data></Key></KeyFile>"
            )
        )
        .err(),
        Some(KdbxRefusal::Malformed)
    );
}

#[test]
fn kdbx3_alterations_are_rejected() {
    let file = PYKEEPASS_KDBX3_AESKDF;
    // Header fields end with id 0 and a 16-bit length.
    let mut end = 12;
    loop {
        let id = file[end];
        let len = u16::from_le_bytes([file[end + 1], file[end + 2]]) as usize;
        end += 3 + len;
        if id == 0 {
            break;
        }
    }
    // A flipped byte in the ciphertext: padding, start bytes or a block hash.
    for pos in [end + 5, end + 100, file.len() - 1] {
        let mut f = file.to_vec();
        f[pos] ^= 1;
        assert!(
            matches!(
                read(&f, PASSWORD).err(),
                Some(KdbxRefusal::WrongKey | KdbxRefusal::Malformed)
            ),
            "{pos}"
        );
    }
    // Truncated.
    assert!(read(&file[..file.len() - 16], PASSWORD).is_err());
    // Rounds beyond the bound: refused before any computation.
    let mut f = file.to_vec();
    let mut pos = 12;
    loop {
        let id = f[pos];
        let len = u16::from_le_bytes([f[pos + 1], f[pos + 2]]) as usize;
        if id == 6 {
            f[pos + 3..pos + 11].copy_from_slice(&u64::MAX.to_le_bytes());
            break;
        }
        pos += 3 + len;
    }
    assert_eq!(read(&f, PASSWORD).err(), Some(KdbxRefusal::Unsupported));
}

#[test]
fn kdbx3_hashed_blocks() {
    let block = b"payload";
    let mut data = Vec::new();
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&hirzla_crypto::kdbx::sha256(block));
    data.extend_from_slice(&7i32.to_le_bytes());
    data.extend_from_slice(block);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&[0; 32]);
    data.extend_from_slice(&0i32.to_le_bytes());
    assert_eq!(super::hashed_blocks(&data).unwrap().as_slice(), block);
    // Wrong index, wrong hash, non-zero final hash, trailing bytes, missing final block.
    let mut bad_index = data.clone();
    bad_index[0] = 1;
    let mut bad_hash = data.clone();
    bad_hash[4] ^= 1;
    let mut bad_final = data.clone();
    bad_final[47 + 4] = 1;
    let mut trailing = data.clone();
    trailing.push(0);
    for bad in [
        &bad_index,
        &bad_hash,
        &bad_final,
        &trailing,
        &data[..47].to_vec(),
    ] {
        assert_eq!(
            super::hashed_blocks(bad).err(),
            Some(KdbxRefusal::Malformed)
        );
    }
}

#[test]
fn kdbx_times() {
    // KDBX 4: base64 of LE64 seconds from 0001-01-01. 2027-03-01T12:30:00Z.
    let secs: i64 = 62_135_596_800 + 1_803_904_200;
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        secs.to_le_bytes(),
    );
    assert_eq!(
        super::xml::kdbx_time(&b64).as_deref(),
        Some("2027-03-01T12:30:00Z")
    );
    // Leap day, and the epoch of KeePass.
    let leap: i64 = 62_135_596_800 + 951_782_400;
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        leap.to_le_bytes(),
    );
    assert_eq!(
        super::xml::kdbx_time(&b64).as_deref(),
        Some("2000-02-29T00:00:00Z")
    );
    assert_eq!(
        super::xml::kdbx_time("2027-03-01T12:30:00Z").as_deref(),
        Some("2027-03-01T12:30:00Z")
    );
    assert_eq!(super::xml::kdbx_time("pas une date"), None);
    assert_eq!(super::xml::kdbx_time("AAAA"), None);
}

#[test]
fn kdbx3_header_hash_is_checked() {
    // A comment field inserted in the header changes no key: only `Meta/HeaderHash`, which
    // KeePassXC wrote, tells.
    let mut f = KEEPASSXC_KDBX3_AESKDF[..12].to_vec();
    f.extend_from_slice(&[1, 2, 0, b'h', b'i']);
    f.extend_from_slice(&KEEPASSXC_KDBX3_AESKDF[12..]);
    assert_eq!(read(&f, PASSWORD).err(), Some(KdbxRefusal::Malformed));
}
