# Prototypes de garde matérielle (étape 5)

ADR 0014. Avant d'écrire l'interface `Keystore`, un prototype minimal par système dit ce qui
marche réellement. Ce document rapporte les résultats et décrit les tests à lancer à la main
sur du vrai matériel.

## Résultats au 2026-11-13

| Système | Prototype | Testé ? | Résultat |
| --- | --- | --- | --- |
| Linux, TPM 2.0 | `tpm2_prototype` (`tss-esapi` 7.7.0, tpm2-tss 4.0.1) | **Oui, contre swtpm 0.7.3** (Ubuntu 24.04, WSL) | 5 tests sur 5 |
| Linux, vraie puce | même code | **Non**, faute de machine | — |
| Windows, TPM 2.0 | **aucun** | **Non** | Bloqué : voir ci-dessous |
| macOS, Secure Enclave | `secure_enclave_prototype` (`security-framework` 3.7.0) | **Non**, faute de Mac | Contrôle de types et Clippy pour `aarch64-apple-darwin` seulement |

### Linux contre swtpm

| Vérifié | Observation |
| --- | --- |
| Sceller puis desceller 32 octets, aussi après une nouvelle connexion | Oui. Objet stocké : 46 octets de partie publique et 158 octets de partie privée. Le secret n'apparaît pas dans le blob |
| Clé de stockage avec enfants en AES-256-CFB | Oui sur swtpm (repli prévu sur AES-128) |
| Blob altéré | Refusé par la puce : « integrity check failed » |
| PIN | Le bon PIN descelle, un mauvais est refusé et incrémente le compteur d'attaques par dictionnaire de la puce |
| Clé de stockage substituée (interposition sur le bus) | Refusée avant le descellement : le nom de la clé est enregistré avec l'objet |
| Compteur NV de type `counter` | Monte de 1 en 1, survit à une reconnexion ; incrément refusé sans son autorisation aléatoire ; un compteur supprimé puis recréé repart au-dessus de la plus haute valeur atteinte (4 après 3) : il ne peut pas être remis à zéro |

À noter :

- tpm2-tss écrit ses propres messages d'erreur sur la sortie d'erreur (`WARNING:esys…`). Il
  faudra les couper (`TSS2_LOG=all+none`) dans les binaires livrés.
- Le compteur se définit sous la hiérarchie propriétaire, dont l'autorisation est vide sur
  swtpm et sur la plupart des PC Linux.

### Windows : bloqué

La décision 4 de l'ADR 0014 (`tss-esapi` partout) n'est pas réalisable aujourd'hui :

- `tss-esapi` 7.7.0 et 8.0.0-alpha.4 ne savent pas ouvrir le TCTI `tbs` de Windows
  (`TctiNameConf` ne connaît que `device`, `mssim`, `swtpm` et `tabrmd`) ;
- `tss-esapi-sys` 0.6.0 n'a pas de bindings pré-générés pour Windows. Ils ont été ajoutés en
  amont le 2026-11-12 (pull request #692) mais ne sont pas encore publiés.

Rien n'est donc compilé pour le TPM sous Windows. Les choix possibles sont proposés dans le
résumé de l'étape. La question 3 (le compteur) peut en revanche être tranchée dès maintenant
par le test manuel W2, qui n'a pas besoin de `tss-esapi`.

### macOS : à tester

Le prototype suit la décision 1 : la clé de l'enclave n'est qu'un facteur, à combiner avec
le mot de passe.

- À l'enrôlement, une clé P-256 logicielle `E` est tirée, `S = ECDH(E, SE_pub)` est calculé
  et seule `E_pub` est gardée.
- Au déverrouillage, l'enclave recalcule `S`.
- La clé publique de l'enclave n'est jamais écrite.

Il contient les premiers blocs `unsafe` de la caisse (`SecKeyCreateWithData`, sans enveloppe
sûre dans `security-framework`), chacun justifié par un commentaire `// SAFETY:`.

macOS n'expose aucun compteur monotone aux applications : la Secure Enclave n'en déclarera pas.

## Tests à lancer à la main

Les sorties de ces tests ne contiennent aucun secret : on peut les copier telles quelles dans
une issue ou un message.

### L1 — Linux avec une vraie puce TPM 2.0

```sh
sudo apt-get install -y build-essential pkg-config cmake clang libtss2-dev tpm2-tools
sudo usermod -aG tss "$USER"        # accès à /dev/tpmrm0 ; se reconnecter ensuite
tpm2_getcap properties-variable | grep -E 'ownerAuthSet|lockoutAuthSet|inLockout'
tpm2_getcap properties-fixed | grep -A1 -E 'TPM2_PT_MANUFACTURER|TPM2_PT_FIRMWARE_VERSION_1'
cargo test -p hirzla-keystore --test tpm2_prototype -- --ignored --nocapture --test-threads=1
```

Attendu : 5 tests réussis. Le test du PIN compte un échec dans le compteur d'attaques par
dictionnaire de la puce (sans conséquence). Le test du compteur crée puis supprime un index
NV. Si `ownerAuthSet: 1`, ce test échoue à la création : c'est l'information recherchée,
rien n'est cassé.

### W1 — Windows : identifier la puce (sans privilèges)

Sur un PC Windows **avec un TPM 2.0**. Ce poste-ci a un TPM 1.2 vulnérable à ROCA et ne
convient pas.

```powershell
tpmtool getdeviceinformation
```

À rapporter : version du TPM (doit être 2.0), fabricant, version du micrologiciel, ligne
« vulnérable ».

### W2 — Windows : Windows a-t-il posé une autorisation propriétaire ? (question 3)

Démarrer **le même PC** sur une clé USB Ubuntu 24.04 en mode live (sans installer), puis :

```sh
sudo apt-get install -y tpm2-tools
sudo tpm2_getcap properties-variable | grep -E 'ownerAuthSet|lockoutAuthSet'
```

- `ownerAuthSet: 0` : Windows a laissé l'autorisation du propriétaire vide. Une application
  pourra créer un compteur, à confirmer par L1 lancé depuis cette session live.
- `ownerAuthSet: 1` : Windows l'a posée puis oubliée. Aucune application ne peut créer de
  compteur, et Windows déclarera ne pas en avoir (décision 3).

Précautions :

- ne rien effacer ni réinitialiser dans le TPM ;
- avoir la clé de récupération BitLocker sous la main avant de démarrer sur la clé USB, au
  cas où le micrologiciel la demanderait au retour sous Windows.

### M1 — macOS, Secure Enclave (Mac Apple silicon ou avec puce T2)

```sh
xcode-select --install              # si les outils en ligne de commande manquent
cargo test -p hirzla-keystore --test secure_enclave_prototype -- --ignored --nocapture --test-threads=1
```

Attendu :

- `enclave_in_memory_key_agreement` réussit ;
- `enclave_keychain_persistence` affiche probablement « refused: Security framework error
  -34018 », car le binaire de test n'est pas signé avec le droit `keychain-access-groups`.
  C'est l'information recherchée ;
- `enclave_user_presence` demande Touch ID ou le mot de passe de session et réussit si l'on
  accepte.

À rapporter : la sortie complète, le modèle du Mac et la version de macOS.
