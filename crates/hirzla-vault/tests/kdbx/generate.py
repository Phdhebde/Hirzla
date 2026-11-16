"""Bases de référence KDBX 4 pour les tests de l'import (ADR 0025).

Écrites par pykeepass 4.2.0 (pycryptodome, argon2-cffi), une implémentation indépendante de
celle de Hirzla, à partir du modèle vide qu'elle embarque (KDBX 4.0, AES-256, Argon2d). Le
contenu reprend celui de `source.xml`. Mot de passe de test : « hirzla-test ».

    python3 -m venv /tmp/kp && /tmp/kp/bin/pip install pykeepass==4.2.0
    /tmp/kp/bin/python -I generate.py SORTIE

`generate.sh` enchaîne ce script, puis fait réécrire une base par KeePassXC.
"""

import os
import sys

from pykeepass import create_database
from pykeepass.kdbx_parsing import kdf_uuids

PASSWORD = "hirzla-test"
OUT = sys.argv[1]


def tune(kp, cipher, kdf, compress):
    """Chiffrement, dérivation (coût réduit pour des tests rapides) et compression."""
    h = kp.kdbx.header.value.dynamic_header
    h.cipher_id.data = cipher
    h.encryption_iv.data = os.urandom(12 if cipher == "chacha20" else 16)
    params = h.kdf_parameters.data.dict
    params["$UUID"].value = kdf_uuids[kdf]
    params["M"].value = 8 * 1024 * 1024
    params["I"].value = 2
    params["P"].value = 2
    h.compression_flags.data.compression = compress


def fill(kp):
    root = kp.root_group
    root.name = "Base de test"
    kp.add_entry(root, "", "", "x", url="https://sans-titre.example")
    kp.add_entry(root, "Note seule", "", "", notes="Rien d'autre")
    kp.add_entry(root, "Vide", "", "")

    internet = kp.add_group(root, "Internet")
    mail = kp.add_group(internet, "Mail")
    e = kp.add_entry(mail, "Messagerie", "alice@example.org", "ancien-mot-de-passe")
    e.save_history()
    e.password = "mot-de-passe-très-secret"
    e.url = "https://mail.example.org"
    e.notes = "Ligne 1\nLigne 2 & <spécial>"
    e.tags = ["perso", "mail"]
    e.set_custom_property("Question secrète", "Nom du chat", protect=True)
    e.set_custom_property("Numéro client", "12345")
    e.otp = "otpauth://totp/Exemple:alice?secret=JBSWY3DPEHPK3PXP&issuer=Exemple"

    banque = kp.add_group(root, "Banque")
    b = kp.add_entry(banque, "Banque", "bob", "Pa55w0rd!")
    att = kp.add_binary("Relevé de compte\n".encode())
    b.add_attachment(att, "releve.txt")

    gone = kp.add_entry(root, "Supprimé", "", "corbeille")
    kp.trash_entry(gone)


def make(name, cipher, kdf, compress, content=True):
    kp = create_database(os.path.join(OUT, name), password=PASSWORD)
    tune(kp, cipher, kdf, compress)
    if content:
        fill(kp)
    kp.save()


make("pykeepass-aes-argon2d.kdbx", "aes256", "argon2", True)
make("pykeepass-chacha20-argon2id.kdbx", "chacha20", "argon2id", True)
make("pykeepass-aes-argon2id-plain.kdbx", "aes256", "argon2id", False)
make("pykeepass-chacha20-argon2d-plain.kdbx", "chacha20", "argon2", False)
# Empty targets for KeePassXC, which keeps their cipher and KDF when it rewrites them.
make("keepassxc-aes-argon2d.kdbx", "aes256", "argon2", True, content=False)
make("keepassxc-chacha20-argon2id.kdbx", "chacha20", "argon2id", True, content=False)
