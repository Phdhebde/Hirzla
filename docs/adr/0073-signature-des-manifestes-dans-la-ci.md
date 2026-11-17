# ADR 0073 — Signature des manifestes des clients dans la CI

- Statut : accepté (2026-11-17, décision de l'éditeur, risque accepté)
- Date : 2026-11-17
- Remplace : la signature hors ligne entre les deux étapes de l'ADR 0064 (points 1 à 3 et 4
  pour ce qui touche au manifeste) ; déroge, pour le manifeste des clients, à la règle
  « la clé d'éditeur ne quitte pas le poste de signature hors ligne » des ADR 0043 (point 6)
  et 0063.

## Contexte

Le flux en deux temps de l'ADR 0064 demande à l'éditeur, à chaque version, environ quatre
gestes manuels : télécharger l'artefact `hirzla-X.Y.Z-a-signer`, le porter sur le poste de
signature hors ligne et y lancer `signer-manifestes.sh`, joindre les trois manifestes au
brouillon, puis lancer à la main la seconde étape. L'essai à blanc du 2026-11-16 a validé ce
flux de bout en bout et en a montré la friction : transferts par clé USB, artefacts qui
expirent, étape 2 à relancer sur la bonne étiquette, marqueur caché du brouillon à ne pas
toucher.

L'éditeur décide de faire signer les manifestes des clients par la CI, en connaissance du
risque, et d'y brancher la signature Authenticode gratuite de la SignPath Foundation
(ADR 0063, point 4).

## Décision

Une **seule exécution** du flux `Livraison`, à la pose de l'étiquette `vX.Y.Z`, produit un
brouillon de version complet ; l'éditeur n'a plus qu'à approuver la signature, signer
`SHA256SUMS` en GPG et publier.

1. **Clé d'éditeur en secret d'un environnement protégé.** `editeur.cle` (fichier binaire non
   chiffré produit par `hirzla-signer cle-generer`) est stockée en base64 dans le secret
   `HIRZLA_PUBLISHER_KEY` de l'environnement GitHub **`editeur`** ; la clé jetable des essais
   à blanc, dans `HIRZLA_PUBLISHER_KEY_ESSAI` du même environnement. Règles de
   l'environnement : déploiement réservé aux étiquettes `v*` ; l'éditeur est relecteur
   obligatoire, si bien que le job de signature attend un clic d'approbation.
2. **Un seul job voit la clé** (`manifests`), et dans ce job une seule étape. Il récupère
   les exécutables de la même exécution, compile `hirzla-signer` depuis le commit de
   l'étiquette (`cargo build --locked --release -p hirzla-release-signer`), **puis**
   décode la clé dans `$RUNNER_TEMP` sous `umask 077`, la fait lire par `hirzla-signer`
   seul, et la supprime à la fin de l'étape (et encore dans une étape `always()`). Aucune
   autre étape ni aucun autre job n'a le secret dans son environnement ; un essai à blanc ne
   reçoit jamais le secret de la vraie clé, ni l'inverse.
3. **Vérification par les clés publiques compilées.** Chaque manifeste est aussitôt vérifié
   par `hirzla-signer verifier --cles-hex "$HIRZLA_PUBLISHER_KEYS" --version --plateforme
   --executables` : cela prouve que le secret correspond aux clés publiques compilées dans
   les exécutables, et que le manifeste nomme exactement les quatre exécutables, mêmes
   tailles et mêmes empreintes. Les commandes sont celles de
   `.github/scripts/signer-manifestes.sh`, gardé pour une signature hors ligne de secours.
4. **SignPath, facultatif, avant le manifeste.** Toute signature modifie les octets d'un
   exécutable ; la signature Authenticode des quatre `.exe` (job `authenticode-exe`) a donc
   lieu **avant** le calcul du manifeste Windows, qui porte sur les fichiers signés. Le MSI
   est signé **après** son empaquetage (job `authenticode-msi`) : la signature modifie le
   fichier MSI, pas les fichiers qu'il contient, et le manifeste reste juste. Le jeton
   `SIGNPATH_API_TOKEN` vit dans un environnement `signpath`, réservé aux étiquettes `v*`.
   Si la variable `SIGNPATH_ORGANIZATION_ID` est vide, les deux jobs sont sautés : les
   fichiers Windows restent non signés (avertissement SmartScreen) et le flux va jusqu'au
   bout.
5. **Le reste du flux de l'ADR 0064 ne change pas** : exécutables compilés une seule fois,
   signature ad hoc de `Hirzla.app`, installeurs construits à partir des mêmes fichiers et
   ouverts pour une comparaison octet par octet, `.pkg` macOS (ADR 0065), nomenclatures,
   `SHA256SUMS`, provenance Sigstore, essai à blanc par étiquette `vX.Y.Z-essai.N`. Le flux
   crée lui-même le **brouillon** à la fin ; il ne publie jamais. Le second déclenchement
   manuel, l'artefact `hirzla-X.Y.Z-a-signer` et le marqueur caché du brouillon disparaissent.
6. **Restent manuels** : la signature GPG de `SHA256SUMS` par l'éditeur, et les paquets de
   mise à jour hors ligne `.hirzla-maj` (ADR 0043), que la CI ne produit pas ; l'éditeur les
   signe avec sa copie hors ligne de la clé.

## Conséquences

- Facile : une version, c'est une étiquette, un clic d'approbation, une signature GPG et
  *Publish release*. Plus de transfert par clé USB, plus d'artefact qui expire entre deux
  étapes ; relancer l'exécution suffit après une erreur.
- **Risque accepté** : la clé d'éditeur, racine de confiance des exécutables installés
  (ADR 0042, 0063), est désormais exposée à GitHub. Peuvent obtenir des signatures de
  manifeste, donc faire démarrer un noyau ou un client piégé : quiconque compromet le compte
  GitHub de l'éditeur, le dépôt ou le flux avec le droit de pousser une étiquette et
  d'approuver le déploiement ; une action tierce ou une dépendance compilée dans le job
  `manifests` (elles tournent sur la même machine que l'étape de signature, avant elle) ;
  un agent hébergé par GitHub compromis pendant ce job ; GitHub lui-même. La même clé signe
  les paquets de mise à jour (domaine `hirzla/v1/update-package`) : un attaquant qui la lit
  peut aussi en signer.
- Atténuations : environnement protégé avec relecteur obligatoire et déploiement réservé
  aux étiquettes `v*` ; protection des branches et des étiquettes `v*` recommandée (règles
  du dépôt) ; double authentification du compte de l'éditeur ; dépendances figées par
  `Cargo.lock` et contrôlées par `cargo deny` ; actions épinglées ; provenance Sigstore de
  chaque fichier, qui relie toute livraison à son exécution ; copie hors ligne de la clé et
  procédure de rotation (`livraison.md` § 7 : publier une version qui admet une nouvelle
  clé dans `HIRZLA_PUBLISHER_KEYS`, remplacer le secret).
- Une signature volée ne passe pas inaperçue indéfiniment : toute livraison non produite
  par le flux du dépôt n'a pas d'attestation de provenance valable ; mais le produit ne
  vérifie pas cette attestation lui-même.
- La cible de sécurité (hypothèse H13, menaces résiduelles) déclare ce risque ; un CESTI
  pourra le juger incompatible avec un niveau de qualification visé, auquel cas on revient
  à la signature hors ligne (`signer-manifestes.sh`) ou à un HSM.
- SignPath : la fondation garde la clé Authenticode dans son HSM ; une politique de
  signature peut exiger une approbation dans son interface, ce qui fait attendre le job
  (jusqu'à une heure).

## Alternatives écartées

- **Garder la signature hors ligne (ADR 0064)** : la plus sûre, mais l'éditeur juge la
  friction trop forte pour chaque version ; reste possible en secours.
- **HSM ou KMS en nuage** (clé non exportable, signature à distance) : payant, et aucun
  service courant ne propose ML-DSA-87 avec ECDSA P-384 dans un même objet ; il faudrait
  aussi adapter `hirzla-signer`.
- **Agent de CI auto-hébergé** sur une machine de l'éditeur : une machine connectée de plus à
  maintenir et à durcir, exposée aux exécutions du dépôt ; ne supprime pas le risque d'un
  flux modifié.
- **Signer dans un job sans compilation, avec un `hirzla-signer` compilé ailleurs** : le
  binaire transmis par artefact devrait lui-même être vérifié ; compiler depuis le commit
  de l'étiquette dans le job de signature est plus simple à relire.
