"""Bases de référence « façon KeePass 2 » pour l'import (ADR 0025).

KeePass 2 crée par défaut des bases KDBX 3.1 ou KDBX 4 dérivées par AES-KDF, avec un flux
interne Salsa20 (KDBX 3.1), et des champs propres : TOTP `TimeOtp-*`, HOTP `HmacOtp-*`,
références `{REF:…}`, saisie automatique, expiration, identifiant protégé. Écrites par
pykeepass 4.2.0, implémentation indépendante de celle de Hirzla. Données fictives. Mot de
passe de test : « hirzla-test ».

    python3 -m venv /tmp/kp && /tmp/kp/bin/pip install pykeepass==4.2.0
    /tmp/kp/bin/python -I generate_keepass2.py DOSSIER

Le dossier doit contenir `keepassxc-kdbx3-aeskdf.kdbx` (voir `generate.sh`) : pykeepass ne
crée pas de KDBX 3.1 vide, il réécrit cette base après l'avoir vidée.

Bases écrites :

- `pykeepass-kdbx3-aeskdf.kdbx` : KDBX 3.1, AES-256, AES-KDF (1 000 tours), Salsa20, gzip ;
- `pykeepass-kdbx4-aeskdf.kdbx` : KDBX 4, ChaCha20, AES-KDF (1 000 tours), gzip ;
- `pykeepass-keyfile.kdbx` et `keyfile-v2.keyx` : KDBX 4, mot de passe et fichier clé XML
  version 2.0 ;
- `pykeepass-keyfile-only.kdbx` et `keyfile-raw.bin` : KDBX 4, fichier clé seul (32 octets
  bruts).
"""

import datetime
import os
import sys

from construct import Container
from pykeepass import PyKeePass, create_database
from pykeepass.kdbx_parsing import kdf_uuids

PASSWORD = "hirzla-test"
OUT = sys.argv[1]
ROUNDS = 1000
MAIL_UUID = "0123456789abcdef0123456789abcdef"


def clear(kp):
    root = kp.root_group
    for e in list(root.entries):
        kp.delete_entry(e)
    for g in list(root.subgroups):
        kp.delete_group(g)


def fill(kp):
    import uuid

    root = kp.root_group
    root.name = "Base KeePass 2"

    internet = kp.add_group(root, "Internet")
    mail = kp.add_entry(internet, "Messagerie", "alice@example.org", "mot-de-passe-très-secret")
    mail.uuid = uuid.UUID(MAIL_UUID)
    mail.url = "https://mail.example.org"

    # Identifiant et adresse, sans mot de passe : gardée.
    kp.add_entry(internet, "Forum", "alice", "", url="https://forum.example.org")
    # Adresse seule.
    kp.add_entry(internet, "", "", "", url="https://adresse-seule.example")
    # Titre seul : vide.
    kp.add_entry(root, "Titre seul", "", "")
    # Identifiant fait d'espaces : écarté, l'entrée garde son mot de passe.
    kp.add_entry(root, "Espaces", "   ", "p")

    # Identifiant protégé, comme le permet KeePass 2.
    prot = kp.add_entry(root, "Protégé", "", "secret")
    prot._set_string_field("UserName", "utilisateur-protégé", True)

    # Références vers « Messagerie ».
    ref = MAIL_UUID.upper()
    r = kp.add_entry(root, "Référence", "{REF:U@I:%s}" % ref, "{REF:P@I:%s}" % ref)
    r.notes = "Voir {REF:T@I:%s} ; inconnue {REF:U@I:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF} ; {REF:U@T:Messagerie}" % ref

    # Expiration et saisie automatique.
    exp = kp.add_entry(root, "Expire", "bob", "x")
    exp.expires = True
    exp.expiry_time = datetime.datetime(2027, 3, 1, 12, 30, 0, tzinfo=datetime.timezone.utc)
    exp.autotype_sequence = "{USERNAME}{TAB}{PASSWORD}{ENTER}"
    exp.autotype_window = "Connexion - Navigateur"

    # TOTP de KeePass 2 : secret en base64 (décodable), SHA-256, 8 chiffres, 60 s.
    t = kp.add_entry(root, "TOTP KeePass", "carol", "y")
    t._set_string_field("TimeOtp-Secret-Base64", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=", True)
    t._set_string_field("TimeOtp-Algorithm", "HMAC-SHA-256", False)
    t._set_string_field("TimeOtp-Length", "8", False)
    t._set_string_field("TimeOtp-Period", "60", False)
    # TOTP en base32, et HOTP : gardés en champs.
    b = kp.add_entry(root, "TOTP base32", "dave", "z")
    b._set_string_field("TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", True)
    h = kp.add_entry(root, "HOTP", "erin", "w")
    h._set_string_field("HmacOtp-Secret", "12345678901234567890", True)
    h._set_string_field("HmacOtp-Counter", "3", False)

    # Pièces jointes : deux sur une entrée, une partagée avec une autre.
    docs = kp.add_group(root, "Documents")
    shared = kp.add_binary(b"contenu partage\n", compressed=True, protected=True)
    other = kp.add_binary(bytes(range(256)), compressed=False, protected=False)
    a1 = kp.add_entry(docs, "Contrat", "", "", notes="Pièces jointes")
    a1.add_attachment(shared, "contrat.pdf")
    a1.add_attachment(other, "donnees.bin")
    a2 = kp.add_entry(docs, "Copie", "", "", notes="Même pièce")
    a2.add_attachment(shared, "copie.txt")

    # Chemin de groupe plus long que l'étiquette (128 octets).
    g = root
    for i in range(6):
        g = kp.add_group(g, "Groupe de niveau %d avec un nom assez long" % i)
    kp.add_entry(g, "Profond", "frank", "v")


def aes_kdf(kp):
    """AES-KDF in a KDBX 4 header, in place of Argon2."""
    h = kp.kdbx.header.value.dynamic_header
    d = h.kdf_parameters.data.dict
    for k in ("M", "I", "P", "V"):
        d.pop(k, None)
    d["$UUID"].value = kdf_uuids["aeskdf"]
    d["S"].value = os.urandom(32)
    d["R"] = Container(type=0x05, key="R", value=ROUNDS, next_byte=0)
    keys = list(d.keys())
    for k in keys:
        d[k].next_byte = 0 if k == keys[-1] else 1


def tune4(kp, cipher):
    h = kp.kdbx.header.value.dynamic_header
    h.cipher_id.data = cipher
    h.encryption_iv.data = os.urandom(12 if cipher == "chacha20" else 16)
    params = h.kdf_parameters.data.dict
    params["M"].value = 8 * 1024 * 1024
    params["I"].value = 2
    params["P"].value = 2


# KDBX 3.1 from the KeePassXC base, emptied and refilled.
kp = PyKeePass(os.path.join(OUT, "keepassxc-kdbx3-aeskdf.kdbx"), password=PASSWORD)
assert kp.version == (3, 1), kp.version
kp.kdbx.header.value.dynamic_header.transform_rounds.data = ROUNDS
clear(kp)
fill(kp)
# pykeepass keeps the `Meta/HeaderHash` of the file it read, and draws new seeds at each save:
# the hash would not match. It is optional (KDBX 3.0 has none): removed. The KeePassXC base
# keeps a valid one.
meta = kp.tree.find("Meta")
meta.remove(meta.find("HeaderHash"))
kp.save(os.path.join(OUT, "pykeepass-kdbx3-aeskdf.kdbx"))

kp = create_database(os.path.join(OUT, "pykeepass-kdbx4-aeskdf.kdbx"), password=PASSWORD)
tune4(kp, "chacha20")
aes_kdf(kp)
fill(kp)
kp.save()

# Key files: XML version 2.0 (KeePass 2.4x), and 32 raw bytes.
key = bytes(range(32))
with open(os.path.join(OUT, "keyfile-v2.keyx"), "w", encoding="utf-8") as f:
    hexkey = key.hex().upper()
    f.write(
        '<?xml version="1.0" encoding="utf-8"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n'
        "\t</Meta>\n\t<Key>\n\t\t<Data Hash=\"630DCD29\">\n\t\t\t%s %s\n\t\t</Data>\n\t</Key>\n</KeyFile>\n"
        % (hexkey[:32], hexkey[32:])
    )
with open(os.path.join(OUT, "keyfile-raw.bin"), "wb") as f:
    f.write(bytes(range(100, 132)))

kp = create_database(
    os.path.join(OUT, "pykeepass-keyfile.kdbx"),
    password=PASSWORD,
    keyfile=os.path.join(OUT, "keyfile-v2.keyx"),
)
tune4(kp, "aes256")
kp.add_entry(kp.root_group, "Fichier clé", "kim", "k")
kp.save()

kp = create_database(
    os.path.join(OUT, "pykeepass-keyfile-only.kdbx"),
    keyfile=os.path.join(OUT, "keyfile-raw.bin"),
)
tune4(kp, "aes256")
kp.add_entry(kp.root_group, "Fichier seul", "lou", "l")
kp.save()
