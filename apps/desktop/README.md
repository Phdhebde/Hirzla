# Application de poste

Application Tauri 2 pour Windows, Linux et macOS, modes Self et Serveur (étape 7 de
`PROMPTS.md`).
Décisions : ADR 0024 (coquille et interface), ADR 0025 (import KeePass), ADR 0033
(verrouillage à la mise en veille et au verrouillage de session), ADR 0034 (kit de
recouvrement), ADR 0041 (écrans du mode Serveur). Livraison : `docs/livraison.md`.

L'application est un **client du noyau**, comme la ligne de commande : elle ne détient
aucune clé. Son processus Rust parle à `hirzla-core` par le canal local authentifié
(`docs/api-locale.md`) ; la vue web ne parle qu'à ce processus, par les commandes de
`src-tauri/src/commands.rs` et `src-tauri/src/selfmode.rs`, sous une politique de contenu
stricte, sans réseau ni greffon.

Fonctions du mode Self (API locale version 5, `docs/api-locale.md` § 16) : réglages du
coffre (délais, verrouillage à la mise en veille et au verrouillage de session), changement
du mot de passe maître, historique des versions et restauration, sortie de corbeille, kit de
recouvrement à quorum (création, ouverture du coffre avec les parts, retrait) et import
KeePass KDBX 4 lu par le noyau. Les fichiers (base KeePass, parts) sont choisis par le
sélecteur du système, ouvert par le processus Rust : la vue web ne reçoit que des noms.

Fonctions du mode Serveur (API locale version 4, `docs/api-locale.md` § 15, ADR 0041),
dans `src-tauri/src/servermode.rs` et `ui/js/server.js` : rejoindre un serveur (adresse,
certificat de l'AC du site choisi par le sélecteur du système, empreinte de l'invitation),
confirmer son empreinte comparée hors bande, exporter sa clé publique de membre pour
l'administrateur, synchroniser, état de la connexion et de la dernière synchronisation,
casiers partagés (marqués « Partagé » dans la liste), création d'un casier partagé, membres
et rôles. Les droits affichés (boutons actifs ou désactivés, avec leur motif) sont ceux que
le noyau calcule : l'interface ne recopie pas les règles de `roles.md`. Un registre de
transparence suspect, une alerte sur vos clés, un accès perdu ou une empreinte à confirmer
s'affichent dans un bandeau du coffre ouvert.

Sous Linux, l'application écoute logind et l'économiseur d'écran sur D-Bus
(`src-tauri/src/events.rs`) et signale la mise en veille et le verrouillage de session au
noyau ; sous Windows et macOS, le noyau les reçoit lui-même du système.

| Chemin | Rôle |
| --- | --- |
| `ui/` | Interface : HTML, CSS, JavaScript modules, sans framework ni construction. Embarquée telle quelle. |
| `ui/fonts/` | Space Grotesk, Inter, JetBrains Mono (OFL 1.1), empreintes dans `SHA256SUMS`. |
| `ui/css/tokens.css`, `ui/img/` | Copies conformes de `brand/` (vérifiées par les tests). |
| `src-tauri/` | Processus Rust `hirzla-desktop` (membre de l'espace de travail Cargo). |
| `src-tauri/capabilities/main.json` | Ce que la fenêtre peut appeler : les commandes de l'application, rien d'autre. |
| `tests/mock-core.js`, `scripts/captures.mjs` | Faux noyau et captures d'écran (jamais embarqués). |

## Construire et tester

Sous Linux, il faut WebKitGTK 4.1 et GTK 3 :

```sh
sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
```

Puis, depuis la racine du dépôt, les commandes habituelles couvrent l'application :

```sh
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # dont src-tauri/tests/core_e2e.rs, contre un vrai noyau
```

Lancer l'application en développement : `cargo run -p hirzla-desktop`. Le noyau doit être à
côté de l'exécutable (`cargo build -p hirzla-core` le place dans `target/debug/`) ;
l'application le démarre s'il ne tourne pas. `HIRZLA_SOCKET` et `HIRZLA_VAULT` sont transmis
comme pour la ligne de commande.

Interface :

```sh
cd apps/desktop
npm ci --ignore-scripts && npm run check           # vérification des types (JSDoc)
(cd ui/fonts && sha256sum -c SHA256SUMS)            # polices embarquées
NODE_PATH="$(npm root -g)" node scripts/captures.mjs /chemin/des/captures   # Playwright requis
# CHROME_PATH=/usr/bin/google-chrome : un Chrome installé au lieu de celui de Playwright
```

## Polices

Fichiers variables pris dans `google/fonts`, commit
`cc39c4c2c304bc368c9b7c311ea2bcc6013299fe` : `ofl/spacegrotesk/SpaceGrotesk[wght].ttf`,
`ofl/inter/Inter[opsz,wght].ttf`, `ofl/jetbrainsmono/JetBrainsMono[wght].ttf` et les `OFL.txt`
correspondants (aucun nom de fonte réservé). Pour les mettre à jour : télécharger les mêmes
chemins à un nouveau commit, renommer comme dans `ui/fonts/`, régénérer `SHA256SUMS` et mettre
à jour le commit ici et dans `ui/css/fonts.css`.

## Icônes

`src-tauri/icons/` est produit par `scripts/icones.sh` (rsvg-convert, Pillow) à partir de
`src-tauri/icons/source/`, elles-mêmes tirées de `brand/logo/`. Les fichiers produits sont
versionnés : la construction ne les régénère pas.

## Clavier

| Touche | Action |
| --- | --- |
| Ctrl+F (Cmd+F) | Filtrer la liste |
| Ctrl+K (Cmd+K) | Palette : aller à un secret ou à une action, Ctrl+Entrée copie le mot de passe |
| Ctrl+N | Nouveau secret |
| Ctrl+G | Générateur |
| Ctrl+L | Verrouiller |
| Flèches, Début, Fin | Parcourir la liste ; Entrée va à la fiche |
| Échap | Fermer une fenêtre, vider la recherche |

Tout le reste se fait à la tabulation ; le focus est toujours visible.
