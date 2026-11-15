# ADR 0062 — Licence du produit : Apache 2.0

- Statut : accepté (2026-11-15, décision du mainteneur, sur demande de l'éditeur)
- Date : 2026-11-15

## Contexte

Le dépôt est public depuis le 2026-11-15 mais ne porte aucune licence : juridiquement, personne
ne peut l'utiliser, le modifier ni le redistribuer. La cible de sécurité laissait la rubrique
« Licence du produit » à compléter. L'éditeur (Max, en nom propre) demande une licence open
source adaptée à l'usage en entreprise et dans des milieux sensibles (administrations,
opérateurs d'importance vitale, défense), pour un produit qui vise une CSPN puis une
qualification.

Ce qu'il faut à ces utilisateurs :

- une licence connue de leurs services juridiques, sans clause qui bloque l'intégration dans
  un système d'information fermé ou classifié ;
- une **concession explicite de brevets** des contributeurs, avec sa révocation en cas
  d'attaque en contrefaçon : c'est ce que demandent d'abord les acheteurs publics et les
  grands comptes pour un produit cryptographique ;
- la compatibilité avec les licences des dépendances (`deny.toml` : MIT, Apache 2.0, BSD,
  ISC, Unicode, Zlib, BSL 1.0, MPL 2.0 en dépendances non modifiées) ;
- la liberté pour l'éditeur de proposer plus tard une offre commerciale (support, version
  intégrée à Hornn) sans relicencier.

## Décision

**Apache License 2.0** pour tout le dépôt : crates Rust (`license = "Apache-2.0"` hérité de
l'espace de travail), application de poste, extension, SDK Go, documentation.

- `LICENSE` reprend le texte officiel publié par l'Apache Software Foundation, sans
  modification ; `NOTICE` nomme le produit et ses auteurs.
- Les contributions extérieures sont reçues sous la même licence (clause 5 de la licence,
  sans accord de cession séparé).
- `deny.toml` ne change pas : la liste des licences admises vaut pour les dépendances ; les
  crates du dépôt restent hors de cette liste (`[licenses.private]`).
- La marque « Hirzla », le logo et la charte de `brand/` ne sont pas concédés par la licence
  (clause 6) : un dérivé doit changer de nom.

## Conséquences

- Facile : adoption en entreprise et dans le secteur public, intégration dans des produits
  tiers, y compris Hornn ; licence figurant parmi celles admises pour les logiciels libres
  des administrations françaises.
- Difficile : un tiers peut distribuer une version modifiée fermée. La protection du nom
  (clause 6) et la signature d'éditeur (ADR 0042, 0043, 0063) permettent aux utilisateurs de
  reconnaître les binaires officiels.
- À surveiller : chaque nouvelle dépendance doit rester compatible (contrôle `cargo deny`
  existant) ; la mention de licence des fichiers tiers éventuellement copiés dans le dépôt.

## Alternatives écartées

- **EUPL 1.2** : licence européenne, copyleft, reconnue des administrations. Écartée : le
  copyleft impose aux intégrateurs de publier leurs modifications, ce qui freine l'usage dans
  des systèmes fermés ou classifiés, et elle est moins connue des juristes hors de l'Union.
  Reste un bon choix si l'éditeur veut empêcher les dérivés fermés ; un changement ultérieur
  vers l'EUPL n'est possible que pour les versions à venir.
- **MIT ou BSD** : aucune concession de brevets explicite, point faible pour un produit
  cryptographique.
- **AGPL 3.0 / GPL 3.0** : copyleft fort, rejeté par beaucoup de politiques internes des
  grands comptes ; incompatible avec une intégration dans des produits fermés.
- **Double licence (open source + commerciale)** : demande un accord de cession des
  contributeurs et une structure juridique que l'éditeur n'a pas aujourd'hui.
