# Licence de Hirzla

Hirzla est proposé sous **double licence**. Vous choisissez celle qui vous convient :

1. la **GNU Affero General Public License, version 3 ou ultérieure** (`AGPL-3.0-or-later`),
   ouverte à tous, gratuitement : texte complet dans [LICENSE](LICENSE) ;
2. une **licence commerciale**, accordée par l'auteur de Hirzla, pour qui ne peut pas
   respecter les conditions de l'AGPL.

Titulaire des droits : Max, éditeur en nom propre (voir [NOTICE](NOTICE)). La décision et ses
raisons sont dans l'ADR 0074 (`docs/adr/0074-double-licence-agpl-et-commerciale.md`).

> Cette page résume les deux licences pour vous aider à choisir. Elle n'est pas un avis
> juridique et ne remplace pas le texte de la licence. En cas de doute, consultez votre
> service juridique.

## L'AGPL 3.0, pour tous

Vous pouvez utiliser Hirzla, l'étudier, le modifier et le redistribuer, à titre personnel ou
professionnel, sans rien payer. En échange :

- si vous **distribuez** Hirzla, modifié ou non (installeur, image, appliance), vous
  fournissez le code source correspondant sous la même licence, avec les mentions de
  `LICENSE` et `NOTICE` ;
- si vous **modifiez** Hirzla et que des utilisateurs interagissent avec la version modifiée
  **à travers un réseau**, vous leur proposez le code source de cette version (article 13 de
  l'AGPL). C'est ce qui distingue l'AGPL de la GPL.

## La licence commerciale, pour les autres cas

Elle s'adresse aux organisations qui ne peuvent pas ou ne veulent pas respecter ces
conditions, par exemple pour :

- proposer une version modifiée de Hirzla, notamment du serveur `hirzlad`, comme service en
  réseau (offre hébergée, SaaS) sans en publier le code source ;
- intégrer Hirzla, ou une partie de son code, dans un produit propriétaire distribué à des
  clients ;
- appliquer une politique interne qui interdit les licences AGPL.

Son contenu (périmètre, durée, prix, support) se fixe au cas par cas avec l'auteur.

**Demander une licence commerciale** : écrivez à `[À COMPLÉTER : adresse de contact]` en
indiquant votre organisation, l'usage prévu (composants, nombre de postes ou d'utilisateurs,
distribution ou service) et ce qui vous empêche de suivre l'AGPL.

## En pratique : déployer `hirzlad` dans votre organisation

Cas le plus fréquent : vous installez le serveur `hirzlad` et les postes Hirzla pour vos
équipes, sur votre propre infrastructure.

- **Version non modifiée** (binaires officiels ou compilés depuis ce dépôt sans changement) :
  vous pouvez l'utiliser sans formalité. L'article 13 ne s'applique qu'aux versions
  modifiées ; le code source reste disponible sur le dépôt public, il suffit de ne pas
  empêcher vos utilisateurs d'y accéder. Aucune licence commerciale n'est nécessaire.
- **Version modifiée** utilisée par vos seuls salariés : l'usage interne ne vaut pas
  distribution, mais vos utilisateurs interagissent avec `hirzlad` par le réseau. Proposez-leur
  le code source de votre version (un dépôt interne suffit), ou demandez une licence
  commerciale.
- **Version modifiée** proposée à des tiers (clients, filiales distinctes, public) : vous
  publiez le code source de votre version sous AGPL, ou vous demandez une licence commerciale.
- **Configuration** (fichiers de réglage, rôles, politique de mots de passe) : ce n'est pas
  une modification du programme.

Les commits publiés avant le 2026-11-17 sous Apache 2.0 restent disponibles sous cette
licence pour qui les a obtenus ; toute version ultérieure, y compris la 1.0.0, est sous
double licence.

## Contribuer

Les contributions sont reçues après signature de l'accord de contribution ([CLA.md](CLA.md)) :
vous gardez vos droits d'auteur, et l'auteur peut proposer votre contribution sous les deux
licences. Marche à suivre : [CONTRIBUTING.md](CONTRIBUTING.md).

## Marque

Aucune des deux licences ne concède de droit sur le nom « Hirzla », son logo ni la charte de
`brand/` (l'AGPL le permet, article 7 e). Une version dérivée distribuée par un tiers porte un
autre nom, sauf accord de l'éditeur.

---

## Summary (English)

Hirzla is dual-licensed:

- **GNU AGPL v3 or later** (`AGPL-3.0-or-later`, see [LICENSE](LICENSE)), free for everyone.
  If you distribute Hirzla, or let users interact over a network with a *modified* version
  (section 13), you must offer the corresponding source code under the same licence.
- **Commercial licence** from the author, for those who cannot meet the AGPL terms, e.g.
  offering a modified `hirzlad` as a hosted service without publishing the source, or
  embedding Hirzla in a proprietary product. Contact: `[À COMPLÉTER : adresse de contact]`.

Running an unmodified `hirzlad` inside your organisation requires no commercial licence.
Commits published under Apache-2.0 before 2026-11-17 remain available under Apache-2.0 to
those who obtained them. Contributions require signing the contributor licence agreement
([CLA.md](CLA.md)). This summary is not legal advice.
