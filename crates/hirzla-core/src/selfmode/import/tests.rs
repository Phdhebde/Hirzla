#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use super::*;
use hirzla_vault::kdbx::{KdbxAutoType, KdbxField};

fn z(s: &str) -> Option<Zeroizing<String>> {
    Some(copy(s))
}

fn kf(label: &str, value: &str, protected: bool) -> KdbxField {
    KdbxField {
        label: copy(label),
        value: copy(value),
        protected,
    }
}

fn text(edit: &SecretEdit, field: Field) -> Option<String> {
    edit.set.iter().find_map(|(f, v)| match (f, v) {
        (f, FieldValue::Text(t)) if *f == field => Some(t.as_str().to_owned()),
        _ => None,
    })
}

fn title(edit: &SecretEdit) -> String {
    text(edit, Field::Title).unwrap()
}

fn tags(edit: &SecretEdit) -> Vec<&str> {
    edit.add
        .iter()
        .filter_map(|(k, v)| match (k, v) {
            (SetKind::Tags, SetValue::Text(x)) => Some(x.as_str()),
            _ => None,
        })
        .collect()
}

fn customs(edit: &SecretEdit) -> Vec<(&str, &str, bool)> {
    edit.set_custom
        .iter()
        .map(|(_, c)| (c.label.as_str(), c.value.as_str(), c.sensitive))
        .collect()
}

fn planned(e: KdbxEntry) -> (Planned, ImportReport) {
    let mut r = ImportReport::default();
    let p = plan(e, &mut r).unwrap();
    (p, r)
}

#[test]
fn titles_fall_back() {
    let mut r = ImportReport::default();
    let e = KdbxEntry {
        url: z("https://exemple.org/connexion"),
        password: z("x"),
        ..KdbxEntry::default()
    };
    assert_eq!(title(&plan(e, &mut r).unwrap().edit), "exemple.org");
    let e = KdbxEntry {
        username: z("alice"),
        password: z("x"),
        ..KdbxEntry::default()
    };
    assert_eq!(title(&plan(e, &mut r).unwrap().edit), "alice");
    let e = KdbxEntry {
        title: z("   "),
        password: z("x"),
        ..KdbxEntry::default()
    };
    assert_eq!(title(&plan(e, &mut r).unwrap().edit), UNTITLED);
}

#[test]
fn user_name_and_url_without_password_are_kept() {
    let (p, r) = planned(KdbxEntry {
        title: z("Forum"),
        username: z("alice"),
        url: z("  https://forum.example.org "),
        ..KdbxEntry::default()
    });
    assert_eq!(p.secret_type, SecretType::Password);
    assert_eq!(text(&p.edit, Field::Username).as_deref(), Some("alice"));
    assert_eq!(text(&p.edit, Field::Password), None);
    assert!(
        matches!(&p.edit.add[0], (SetKind::Urls, SetValue::Text(u)) if u.as_str() == "https://forum.example.org")
    );
    assert_eq!(r, ImportReport::default());
    // A user name alone, or a URL alone.
    let (p, _) = planned(KdbxEntry {
        title: z("Compte"),
        username: z(" bob "),
        ..KdbxEntry::default()
    });
    assert_eq!(p.secret_type, SecretType::Password);
    // Kept as written, spaces included.
    assert_eq!(text(&p.edit, Field::Username).as_deref(), Some(" bob "));
    let (p, _) = planned(KdbxEntry {
        url: z("https://seule.example"),
        ..KdbxEntry::default()
    });
    assert_eq!(title(&p.edit), "seule.example");
}

#[test]
fn whitespace_user_name_is_no_value() {
    let mut r = ImportReport::default();
    let e = KdbxEntry {
        title: z("Espaces"),
        username: z("   "),
        ..KdbxEntry::default()
    };
    assert!(plan(e, &mut r).is_none());
    assert_eq!(r.empty, 1);
    let (p, _) = planned(KdbxEntry {
        title: z("Espaces"),
        username: z("\t"),
        password: z("p"),
        ..KdbxEntry::default()
    });
    assert_eq!(text(&p.edit, Field::Username), None);
}

#[test]
fn notes_empty_and_counts() {
    let mut r = ImportReport::default();
    let note = KdbxEntry {
        title: z("N"),
        notes: z("texte"),
        ..KdbxEntry::default()
    };
    assert_eq!(plan(note, &mut r).unwrap().secret_type, SecretType::Note);
    let empty = KdbxEntry {
        title: z("Vide"),
        history: 3,
        custom_skipped: 1,
        attachments_skipped: 2,
        ..KdbxEntry::default()
    };
    assert!(plan(empty, &mut r).is_none());
    assert_eq!(
        r,
        ImportReport {
            empty: 1,
            attachments: 2,
            history: 3,
            custom_skipped: 1,
            ..ImportReport::default()
        }
    );
    // Attachments alone make a note.
    let (p, _) = planned(KdbxEntry {
        title: z("Scan"),
        attachments: vec![KdbxAttachment {
            name: copy("scan.pdf"),
            reference: 0,
        }],
        ..KdbxEntry::default()
    });
    assert_eq!(p.secret_type, SecretType::Note);
    assert_eq!(p.attachments.len(), 1);
}

#[test]
fn group_path_and_custom_fields() {
    let (p, _) = planned(KdbxEntry {
        title: z("Messagerie"),
        password: z("x"),
        group_path: vec![copy("Internet"), copy("Mail")],
        tags: vec![copy("perso"), copy("Internet/Mail")],
        custom: vec![kf("Question", "Chat", true)],
        ..KdbxEntry::default()
    });
    assert_eq!(p.secret_type, SecretType::Password);
    assert_eq!(tags(&p.edit), ["Internet/Mail", "perso"]);
    assert_eq!(customs(&p.edit), [("Question", "Chat", true)]);
}

#[test]
fn values_beyond_bounds_go_to_custom_fields() {
    let long_group = "g".repeat(70);
    let (p, r) = planned(KdbxEntry {
        title: z(&"T".repeat(MAX_TITLE + 10)),
        username: z(&"u".repeat(MAX_USERNAME + 1)),
        password: z(&"p".repeat(MAX_PASSWORD + 1)),
        url: z(&format!("https://{}", "a".repeat(MAX_URL))),
        group_path: vec![copy(&long_group), copy(&long_group)],
        tags: vec![copy(&"t".repeat(MAX_TAG + 1)), copy("court")],
        custom: vec![kf("Énorme", &"v".repeat(MAX_CUSTOM_VALUE + 1), false)],
        ..KdbxEntry::default()
    });
    assert_eq!(title(&p.edit).len(), MAX_TITLE);
    assert_eq!(text(&p.edit, Field::Username), None);
    assert_eq!(text(&p.edit, Field::Password), None);
    assert_eq!(tags(&p.edit), ["court"]);
    let labels: Vec<(&str, bool)> = customs(&p.edit).iter().map(|c| (c.0, c.2)).collect();
    assert_eq!(
        labels,
        [
            ("Titre complet", false),
            ("Identifiant", false),
            ("Mot de passe", true),
            ("Adresse", false),
            ("Groupe KeePass", false),
            ("Étiquettes KeePass", false),
        ]
    );
    assert_eq!(customs(&p.edit)[4].1, format!("{long_group}/{long_group}"));
    // The custom value beyond 64 KiB cannot be kept: counted.
    assert_eq!(r.custom_skipped, 1);
}

#[test]
fn custom_fields_and_attachments_are_bounded() {
    let custom: Vec<KdbxField> = (0..64).map(|i| kf(&format!("k{i}"), "v", false)).collect();
    let attachments: Vec<KdbxAttachment> = (0..70)
        .map(|i| KdbxAttachment {
            name: copy(&format!("f{i}")),
            reference: i,
        })
        .collect();
    let (p, r) = planned(KdbxEntry {
        title: z("Plein"),
        password: z("x"),
        custom,
        custom_skipped: 2,
        expiry: Some("2027-01-01T00:00:00Z".to_owned()),
        attachments,
        ..KdbxEntry::default()
    });
    assert_eq!(p.edit.set_custom.len(), 64);
    // Two skipped by the reader, and the expiry that no longer fits.
    assert_eq!(r.custom_skipped, 3);
    assert_eq!(p.attachments.len(), 64);
    assert_eq!(r.attachments, 6);
}

#[test]
fn totp_converted_or_kept() {
    let (p, r) = planned(KdbxEntry {
        title: z("TOTP"),
        otp: vec![
            kf(
                "TimeOtp-Secret-Base64",
                "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                true,
            ),
            kf("TimeOtp-Period", "60", false),
        ],
        ..KdbxEntry::default()
    });
    assert_eq!(p.secret_type, SecretType::Password);
    assert!(p
        .edit
        .set
        .iter()
        .any(|(f, v)| *f == Field::Totp && matches!(v, FieldValue::Totp(t) if t.period == 60)));
    assert!(p.edit.set_custom.is_empty());
    assert_eq!(r.totp, 0);
    // Base32 in a KeePassXC URI: converted, issuer included.
    let (p, r) = planned(KdbxEntry {
        title: z("TOTP"),
        password: z("x"),
        otp: vec![kf(
            "otp",
            "otpauth://totp/Forge:x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            true,
        )],
        ..KdbxEntry::default()
    });
    assert!(p.edit.set.iter().any(|(f, v)| *f == Field::Totp
        && matches!(v, FieldValue::Totp(t) if t.issuer.as_deref() == Some("Forge"))));
    assert!(p.edit.set_custom.is_empty());
    assert_eq!(r.totp, 0);
    // Not convertible (HOTP URI): kept as written, sensitive, counted.
    let (p, r) = planned(KdbxEntry {
        title: z("TOTP"),
        password: z("x"),
        otp: vec![
            kf("otp", "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ", false),
            kf("TimeOtp-Length", "6", false),
        ],
        ..KdbxEntry::default()
    });
    assert!(!p.edit.set.iter().any(|(f, _)| *f == Field::Totp));
    assert_eq!(
        customs(&p.edit),
        [
            ("otp", "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ", true),
            ("TimeOtp-Length", "6", false)
        ]
    );
    assert_eq!(r.totp, 1);
}

#[test]
fn expiry_and_auto_type() {
    let (p, _) = planned(KdbxEntry {
        title: z("E"),
        password: z("x"),
        expiry: Some("2027-03-01T12:30:00Z".to_owned()),
        auto_type: KdbxAutoType {
            enabled: false,
            sequence: z("{PASSWORD}{ENTER}"),
            associations: vec![
                (copy("Fenêtre*"), copy("")),
                (copy("Autre"), copy("{USERNAME}")),
            ],
        },
        ..KdbxEntry::default()
    });
    assert_eq!(
        customs(&p.edit),
        [
            ("Expiration", "2027-03-01T12:30:00Z", false),
            (
                "Saisie automatique KeePass",
                "Désactivée\nSéquence : {PASSWORD}{ENTER}\nFenêtre : Fenêtre*\nFenêtre : Autre → {USERNAME}",
                true
            )
        ]
    );
}

fn with_uuid(n: u8, title: &str) -> KdbxEntry {
    KdbxEntry {
        uuid: Some([n; 16]),
        title: z(title),
        ..KdbxEntry::default()
    }
}

#[test]
fn references_by_identifier_are_resolved() {
    let target = KdbxEntry {
        username: z("alice"),
        password: z("secret"),
        url: z("https://a.example"),
        notes: z("n"),
        ..with_uuid(0xAB, "Cible")
    };
    let id = "AB".repeat(16);
    let chained = KdbxEntry {
        username: z(&format!("{{REF:U@I:{id}}}")),
        ..with_uuid(0xCD, "Relais")
    };
    let relay = "CD".repeat(16);
    let source = KdbxEntry {
        username: z(&format!("{{ref:u@i:{}}}", id.to_lowercase())),
        password: z(&format!("{{REF:P@I:{id}}}")),
        url: z(&format!("{{REF:A@I:{id}}}/chemin")),
        notes: z(&format!(
            "T={{REF:T@I:{id}}} I={{REF:I@I:{id}}} R={{REF:U@I:{relay}}} \
             X={{REF:U@I:{}}} S={{REF:U@T:Cible}} {{REF:",
            "00".repeat(16)
        )),
        custom: vec![kf("Copie", &format!("{{REF:N@I:{id}}}"), false)],
        ..with_uuid(0xEF, "Source")
    };
    let mut entries = vec![target, chained, source];
    resolve_references(&mut entries);
    let s = &entries[2];
    assert_eq!(s.username.as_deref().map(|z| z.as_str()), Some("alice"));
    assert_eq!(s.password.as_deref().map(|z| z.as_str()), Some("secret"));
    assert_eq!(
        s.url.as_deref().map(|z| z.as_str()),
        Some("https://a.example/chemin")
    );
    assert_eq!(
        s.notes.as_deref().map(|z| z.as_str()).unwrap(),
        format!(
            "T=Cible I={id} R=alice X={{REF:U@I:{}}} S={{REF:U@T:Cible}} {{REF:",
            "00".repeat(16)
        )
    );
    assert_eq!(s.custom[0].value.as_str(), "n");
    assert_eq!(
        entries[1].username.as_deref().map(|z| z.as_str()),
        Some("alice")
    );
}

#[test]
fn reference_cycles_end() {
    let a = KdbxEntry {
        username: z(&format!("x{{REF:U@I:{}}}", "02".repeat(16))),
        ..with_uuid(1, "A")
    };
    let b = KdbxEntry {
        username: z(&format!("y{{REF:U@I:{}}}", "01".repeat(16))),
        ..with_uuid(2, "B")
    };
    let mut entries = vec![a, b];
    resolve_references(&mut entries);
    let u = entries[0].username.as_deref().unwrap();
    assert!(u.starts_with("xyxyx"), "{}", u.as_str());
    assert!(u.len() < 64);
}

#[test]
fn media_types() {
    assert_eq!(media_type("releve.PDF"), "application/pdf");
    assert_eq!(media_type("notes.txt"), "text/plain");
    assert_eq!(media_type("sans-extension"), "application/octet-stream");
}
