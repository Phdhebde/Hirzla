# Prototypes de garde matérielle (étape 5)

ADR 0014. Avant d'écrire l'interface `Keystore`, un prototype minimal par système dit ce qui
marche réellement. Ce document rapporte les résultats et décrit les tests à lancer à la main
sur du vrai matériel.

## Résultats au 2026-11-13

| Système | Prototype | Testé ? | Résultat |
| --- | --- | --- | --- |
| Linux, TPM 2.0 | `tpm2_prototype` (`tss-esapi` 7.7.0) | **Oui, contre swtpm 0.7.3** (Ubuntu 24.04, WSL), avec tpm2-tss 4.0.1 puis **4.1.6** | 5 tests sur 5 dans les deux cas |
| Linux, vraie puce | même code | **Non**, faute de machine | — |
| Windows, TPM 2.0 | **aucun** | **Non** | En attente d'une version publiée de `tss-esapi` (ADR 0014, décision 7) |
| Windows, DPAPI | `dpapi_prototype` (`windows-sys` 0.61.2) | **Oui**, sur le poste de développement (Windows 11) | 3 tests sur 3 ; ils tournent avec la suite ordinaire, donc aussi en CI Windows |
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

Version de tpm2-tss : **4.1.3 au minimum** (bindings de `tss-esapi-sys` 0.6). Ubuntu 24.04
livre 4.0.1 : la CI et le test L1 construisent 4.1.6 avec
`.github/scripts/install-tpm2-tss.sh` (archive figée par SHA-256, signature vérifiée avant
figement). Dans WSL, le binaire de test charge bien `libtss2-esys` depuis `/usr/local`.

### Windows : TPM en attente, DPAPI en repli

La décision 4 de l'ADR 0014 (`tss-esapi` partout) n'est pas réalisable aujourd'hui :

- `tss-esapi` 7.7.0 et 8.0.0-alpha.4 ne savent pas ouvrir le TCTI `tbs` de Windows
  (`TctiNameConf` ne connaît que `device`, `mssim`, `swtpm` et `tabrmd`) ;
- `tss-esapi-sys` 0.6.0 n'a pas de bindings pré-générés pour Windows. Ils ont été ajoutés en
  amont le 2026-11-12 (pull request #692) mais ne sont pas encore publiés.

Décision (ADR 0014, décisions 6 et 7) : attendre une version publiée de `tss-esapi` qui
ouvre `tbs`, puis prototyper le TPM Windows. La question 3 (le compteur) peut être tranchée
dès maintenant par le test manuel W2, qui n'a pas besoin de `tss-esapi`.

En attendant, Windows renforce le mot de passe par un **facteur DPAPI** (`CryptProtectData`,
portée utilisateur), toujours combiné au mot de passe, jamais seul. Vérifié sur ce poste :
aller-retour, facteur absent du blob, deux protections du même facteur différentes, refus
avec une autre entropie, refus d'un blob abîmé ou tronqué. Garanties déclarées : liée au
compte Windows de ce poste ; pas de limitation d'essais matérielle ; pas de compteur ; tout
processus du compte peut desceller le facteur ; en domaine, la clé de secours du domaine
(RSA) permet à un administrateur de le desceller.

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
sudo apt-get install -y build-essential pkg-config cmake clang libssl-dev tpm2-tools
sudo -E .github/scripts/install-tpm2-tss.sh   # tpm2-tss 4.1.6 sous /usr/local
pkg-config --modversion tss2-esys             # doit afficher 4.1.6 (au moins 4.1.3)
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

### W3 — Windows : le facteur DPAPI ne sort pas du compte

Les tests automatiques ne peuvent pas changer de compte. Sur n'importe quel PC Windows :

```powershell
cargo test -p hirzla-keystore --test dpapi_prototype -- --nocapture
```

puis, pour vérifier la liaison au compte, ouvrir une session sous **un autre compte
Windows** du même poste et relancer la même commande sur une copie du dépôt : les tests
doivent passer (chaque compte protège et retrouve ses propres facteurs). Le refus d'un
facteur protégé par un autre compte sera testé avec l'interface `Keystore`, quand le blob
sera stocké dans un coffre ; d'ici là, ce test confirme seulement que DPAPI fonctionne pour
chaque compte.

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
