# ADR 0065 — Manifeste des clients hors du paquet d'application sous macOS

- Statut : accepté (2026-11-16, décision du mainteneur)
- Date : 2026-11-16

## Contexte

Le noyau et ses clients se vérifient par le **manifeste des clients** signé par la clé
d'éditeur hybride, sur les trois systèmes (ADR 0042, 0055, 0063 § 1). Le manifeste est lu à
côté du noyau (`codesign::default_manifest_path`).

Sous macOS, le noyau est dans `Hirzla.app/Contents/MacOS/`. Le **sceau** du paquet
d'application (`Contents/_CodeSignature/CodeResources`) couvre tout fichier de `Contents/`, et
la signature de l'exécutable principal (`hirzla-desktop`), ad hoc comprise, contient
l'empreinte de ce sceau. Un manifeste posé dans le paquet devrait donc contenir l'empreinte
d'un `hirzla-desktop` dont la signature dépend du manifeste : c'est circulaire, donc
impossible (`docs/livraison.md` § 9, point 2). `hirzla-core`, `hirzla` et
`hirzla-native-host`, signés chacun avant le paquet, ne sont pas touchés, mais une livraison
macOS ne pouvait pas faire vérifier `hirzla-desktop`.

Deuxième constat : l'image disque (`.dmg`) produite aujourd'hui s'installe par glisser-déposer.
`Hirzla.app` appartient alors au compte qui l'a glissé : un logiciel malveillant de ce compte
peut remplacer un exécutable du paquet, ce qui contredit l'hypothèse H13 (exécutables posés par
root dans un répertoire non inscriptible) dont dépend le risque résiduel M7 sous macOS
(fichier haché au chemin rendu par `proc_pidpath`, `docs/cible-de-securite.md`).

Contraintes : aucun certificat payant (ADR 0063 § 5 : signature ad hoc par défaut), aucun
réseau (règle 7), aucun `unsafe` hors de `hirzla-keystore` (règle 6), aucune dépendance
nouvelle.

## Décision

Sous macOS, dans une version de livraison, le manifeste des clients est **installé hors du
paquet d'application, à un emplacement fixe réservé à root**, par un **paquet d'installation
`.pkg`** qui remplace l'image disque pour les livraisons.

1. **Emplacement fixe.** `/Library/Application Support/Hirzla/hirzla-clients.manifest`,
   fichier `root:wheel` en `0644`, répertoire `root` en `0755`
   (`codesign::MACOS_MANIFEST_PATH`). Il est fixé **à la compilation** pour une version de
   livraison macOS (`codesign::FIXED_MANIFEST_PATH`, vrai si `target_os = "macos"` et
   fonctionnalité `livraison`) : `default_manifest_path` le rend au noyau comme aux clients
   (`CoreSignature::for_build`), et le noyau **refuse `--client-manifest`**. Les versions de
   développement gardent le manifeste à côté du noyau et l'option `--client-manifest`, pour les
   essais. Windows et Linux ne changent pas : à côté du noyau.
2. **Contrôle de propriété, échec fermé.** Avant de lire le manifeste à cet emplacement, le
   noyau et chaque client vérifient, comme `StrictModes` d'OpenSSH
   (`codesign::open_root_protected`, `std::os::unix::fs::MetadataExt`, sans `unsafe`) :
   - chaque répertoire, du parent du fichier jusqu'à `/`, est un répertoire appartenant à root
     (uid 0) et non inscriptible par son groupe ni par les autres ;
   - le fichier est un fichier ordinaire (un lien symbolique est refusé), appartenant à root et
     non inscriptible par son groupe ni par les autres ;
   - ces propriétés sont relues **sur le fichier ouvert** (même périphérique et même inode que
     le chemin vérifié), et c'est ce descripteur qui est lu : le fichier lu est le fichier
     vérifié.

   La règle elle-même est une fonction pure, `codesign::root_protected(uid, mode)`
   (`uid == 0` et aucun des bits `0o022`), testée sur tous les systèmes. Tout écart arrête :
   `SetupError::ManifestNotProtected` (le noyau ne démarre pas, le client ne parle à aucun
   noyau) ; un fichier ou un répertoire illisible ou absent, `SetupError::Manifest(Io)`. La
   signature du manifeste, sa plateforme et les empreintes restent vérifiées ensuite comme
   avant : le contrôle de propriété s'ajoute, il ne remplace rien.
3. **Paquet `.pkg`.** `.github/scripts/macos-pkg.sh APP MANIFESTE VERSION [SORTIE]` construit,
   avec `pkgbuild` et `productbuild` (outils gratuits d'Apple, présents sur les agents macOS),
   un produit à deux composants :
   - `Hirzla.app` copié par `ditto` (signatures et attributs gardés) vers `/Applications`,
     **non relogeable** (`BundleIsRelocatable` faux : Installer n'écrit pas dans une autre
     copie de `Hirzla.app` trouvée sur le disque) et toujours réécrit
     (`BundleIsVersionChecked` faux), pour rester en phase avec le manifeste ;
   - le manifeste vers `/Library/Application Support/Hirzla/`, en `0644` dans un répertoire
     `0755`, propriété `recommended` (root) ;
   - installation sur le volume système seulement (`enable_localSystem`, jamais dans le
     dossier personnel, où le noyau refuserait le manifeste).

   Le script vérifie avant de construire que la signature de `Hirzla.app` tient
   (`codesign --verify --strict`), que le manifeste est un manifeste des clients macOS et qu'il
   contient l'empreinte SHA-384 de chaque exécutable de `Contents/MacOS/` (contrôle de
   cohérence seulement : le noyau reste seul juge) ; après, que le manifeste du paquet est bien
   à root en `0644` (`pkgutil --expand`, `lsbom`). Installé par Installer avec les droits
   d'administrateur, `Hirzla.app` appartient à root : seul root peut écrire dans le paquet
   d'application, ce qui rapproche macOS de l'hypothèse H13 (limites ci-dessous).
4. **Ordre de production.** (a) `cargo tauri build --bundles app` produit `Hirzla.app` ;
   (b) signature finale du paquet d'application (ad hoc `codesign -s - -o runtime`, ou
   Developer ID) ; (c) les exécutables de `Contents/MacOS/` **tels que signés dans le paquet**
   sont hachés par `hirzla-signer manifeste-clients` sur le poste de signature hors ligne (le
   manifeste n'est plus dans le paquet : il ne change pas le sceau) ; (d) `macos-pkg.sh`
   construit le `.pkg` ; (e) le `.pkg` peut être signé (`HIRZLA_PKG_SIGN_IDENTITY`, certificat
   « Developer ID Installer », payant) et notarisé ; sinon, Gatekeeper avertit une fois. Une
   notarisation agrafée au `.pkg` ne touche pas les exécutables.
5. **Image disque.** Abandonnée pour les **livraisons** macOS : une version de livraison
   installée par une image disque ne trouverait pas son manifeste et refuserait de démarrer
   (échec fermé). Elle reste possible pour les versions de **développement** (cible `dmg` de
   `tauri.conf.json`), qui lisent le manifeste à côté du noyau. Le flux de livraison construit
   `--bundles app` sous macOS puis appelle `macos-pkg.sh`.
6. **Mises à jour.** Sous macOS, une mise à jour est un nouveau `.pkg` (même chemin, même
   contrôle) ; `hirzla mise-a-jour appliquer` reste refusé dans un `.app` (`livraison.md` § 8).

## Conséquences

- Facile : `hirzla-desktop` est enfin vérifié par le noyau sous macOS ; le manifeste et le
  paquet d'application sont indépendants (aucune circularité) ; le contenu de `Hirzla.app`
  n'est plus inscriptible par le compte de l'utilisateur, ce qui resserre M7 ; aucun
  certificat, aucune dépendance, aucun `unsafe`.
- Difficile : un `.pkg` non signé fait avertir Gatekeeper (clic droit › Ouvrir, ou
  `sudo installer -pkg … -target /`) ; l'installation demande les droits d'administrateur ;
  supprimer `Hirzla.app` à la main laisse le manifeste (sans effet : c'est une donnée publique
  signée). Un poste où un administrateur a rendu `/Library` ou `/Library/Application Support`
  inscriptible par un groupe voit le noyau refuser de démarrer : c'est voulu.
- Limites, dites franchement : le manifeste vaut pour toute copie authentique de
  `Hirzla.app` de la même version, où qu'elle soit ; une copie posée par l'utilisateur dans
  son dossier personnel démarre, et y ramène le risque de substitution d'un client entre
  lancement et vérification (M7). `/Applications` est inscriptible par le groupe `admin` :
  un compte administrateur peut, sans élévation, y renommer `Hirzla.app`. Dans les deux cas,
  seuls des fichiers aux empreintes du manifeste sont acceptés, et le manifeste, lui, reste
  hors de portée de ce compte (`/Library/Application Support` est `root:admin` en `0755`).
  Le noyau ne vérifie pas la propriété de son propre répertoire : `/Applications` ne
  passerait pas la règle (`0775`), et le refuser rendrait l'installation de référence
  inutilisable.
- À surveiller : comportement de `pkgbuild` (propriété `recommended`, analyse des paquets
  d'application) et du contrôle de propriété sur des postes réels, non essayés en CI (les tests
  de CI couvrent la règle et ses refus, pas une installation par Installer) ; la cohérence des
  versions entre le `.app` et le manifeste, garantie par le `.pkg` qui pose les deux.

## Mise en œuvre

- `crates/hirzla-core/src/codesign.rs` : `MACOS_MANIFEST_PATH`, `FIXED_MANIFEST_PATH`,
  `default_manifest_path`, `root_protected`, `open_root_protected` (Unix), lecture protégée dans
  `Check::setup` pour une livraison macOS, `SetupError::ManifestNotProtected` ;
  `crates/hirzla-core/src/release.rs` : `read_client_manifest` (lecture d'un fichier déjà
  ouvert) ; `crates/hirzla-core/src/daemon.rs` : `--client-manifest` refusé en livraison macOS,
  message de refus.
- Tests : `root_protection_rule` (fonction pure, propriétaire et bits d'écriture, tous
  systèmes), `open_root_protected_fails_closed` (Unix : chemin relatif, lien, répertoire,
  fichier absent, fichier d'un compte ordinaire ou sous un répertoire inscriptible refusés ; un
  fichier système de root accepté là où il existe), `manifest_location_per_build`,
  `parses_the_client_signature_options`.
- `.github/scripts/macos-pkg.sh` ; le flux `livraison.yml` l'appelle (hors de cette demande de
  fusion).

## Alternatives écartées

- **Manifeste dans `Hirzla.app/Contents/Resources/` ou `Contents/MacOS/`** : couvert par le
  sceau, donc circulaire (contexte).
- **Exclure le manifeste du sceau** (règles de ressources personnalisées,
  `codesign --resource-rules`) : obsolètes depuis OS X 10.10 et refusées par Gatekeeper ; un
  fichier non scellé dans `Contents/` fait échouer `codesign --verify --strict`.
- **Ne pas lister `hirzla-desktop` dans le manifeste macOS** : l'application, qui reçoit le
  mot de passe maître, échapperait au contrôle.
- **Manifeste dans les attributs étendus de `Hirzla.app`** : hors du sceau, mais copiés,
  perdus ou réécrits sans contrôle par le compte propriétaire ; aucun gain sur un fichier
  réservé à root.
- **Manifeste dans `~/Library/Application Support/Hirzla/`** : inscriptible par le compte que
  l'on cherche à protéger d'un logiciel malveillant.
- **Emplacement donné par une option ou une variable d'environnement en livraison** : celui qui
  lance le noyau choisirait le manifeste (par exemple un manifeste authentique plus ancien) ;
  l'emplacement est donc fixé à la compilation.
- **Garder l'image disque pour les livraisons, avec un script d'installation du manifeste à
  lancer à part** : deux gestes, un oubli laisse un noyau qui ne démarre pas, et le paquet
  d'application reste au compte de l'utilisateur (H13 non tenue).
- **Signature Developer ID et vérification `systeme`** : payante (ADR 0063 § 5) ; reste
  possible plus tard par le mode `systeme`, sans manifeste.
