# ADR 0030 — Transport SSH de l'agent de rotation

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte
L'étape 13 demande un agent de rotation qui change le mot de passe sur la cible, SSH d'abord,
puis publie la nouvelle version comme une opération ordinaire (`docs/integration-hornn.md` § 9).
Changer un mot de passe par SSH, c'est : établir une session SSH vers la cible, s'authentifier
avec le mot de passe courant, puis faire exécuter le changement (`passwd` dans un pseudo-terminal
pour le compte lui-même, ou `chpasswd` par un compte d'administration).

Contraintes de `CLAUDE.md` :

- une dépendance qui fait du réseau, manipule des secrets ou contient du `unsafe` exige un ADR ;
- tout asymétrique est hybride : l'échange de clés SSH doit être hybride post-quantique
  (`mlkem768x25519-sha256`, ou à défaut `sntrup761x25519-sha512`), l'authentification de l'hôte
  reste classique (aucune signature d'hôte post-quantique n'est normalisée pour SSH) ;
- bibliothèque auditée, maintenue, sans `unsafe` inutile, versions figées, `cargo deny`.

L'état des crates ci-dessous est celui connu à la rédaction ; il est à revérifier (version,
algorithmes, audits) au moment de trancher.

## Décision
Proposée, **non implémentée** : la rotation est écrite derrière le trait
`hirzla_core::agent::rotation::RotationTransport`, avec un faux transport pour les tests
(`crates/hirzla-core/tests/hornn_sim`). Aucun transport réel n'est livré ; `Rotate` répond
`Unsupported`. Recommandation, à confirmer par le mainteneur : **option B** (client OpenSSH du
système piloté par un processus), parce que c'est la seule implémentation largement relue qui
offre aujourd'hui l'échange hybride par défaut, sans `unsafe` ni code réseau dans le dépôt.

Exigences communes, quelle que soit l'option :

1. Échange de clés limité aux algorithmes hybrides ; refus de toute négociation classique seule.
2. Clé d'hôte épinglée par cible (stockée dans le secret ou dans le casier), jamais
   « confiance au premier contact » silencieuse.
3. Mot de passe passé par un canal qui ne finit ni en argument, ni en variable d'environnement,
   ni dans un journal ; tampons effacés.
4. Délais bornés ; distinction stricte entre « refusé, rien n'a changé » et « issue inconnue »
   (`TransportError::Refused` / `Indeterminate`).

## Options

**A. `russh`** (Rust pur, asynchrone sur `tokio`). Maintenu ; offre `mlkem768x25519-sha256`
dans ses versions récentes. Pas d'audit public connu ; tire `tokio` et un second jeu de
primitives (selon les fonctions activées). Conséquences : intégration propre derrière le trait,
mais une pile réseau et cryptographique non auditée dans le noyau, qui est le processus le plus
sensible. Conformité ANSSI : à justifier, primitives hors de la liste de `docs/crypto.md`.
Complexité moyenne, calendrier court.

**B. Client OpenSSH du système** (`ssh` lancé par le noyau, ou par un processus d'aide durci).
OpenSSH est l'implémentation la plus relue ; `mlkem768x25519-sha256` y est disponible (par
défaut dans les versions récentes) et `sntrup761x25519-sha512` depuis plus longtemps. Le mot de
passe courant passe par `SSH_ASKPASS` vers un petit exécutable d'aide qui le lit sur un tube
hérité, puis le nouveau par l'entrée du pseudo-terminal. Conséquences : aucune dépendance Rust
nouvelle, aucun `unsafe` dans le dépôt, mais une dépendance à la version d'OpenSSH du poste (à
vérifier au démarrage : options `KexAlgorithms` refusées si l'algorithme hybride manque), et une
gestion de pseudo-terminal (via `std::process`, ou via `hirzla-keystore::platform` si un appel
système est nécessaire). Complexité moyenne, calendrier moyen.

**C. `ssh2`** (liaison de `libssh2`, C). Code `unsafe` de liaison, OpenSSL ou mbedTLS, et pas
d'échange post-quantique dans `libssh2` à notre connaissance. Écartée : contraire à la règle 2.

**D. Déléguer le transport à la gateway Go** (`golang.org/x/crypto/ssh`, qui propose
`mlkem768x25519-sha256`). Le noyau tirerait le nouveau mot de passe, le remettrait à la gateway
avec l'ancien, attendrait sa confirmation, puis publierait. Conséquences : rien de SSH dans
Hirzla, mais le nouveau mot de passe sort du noyau vers un processus qui ne sait pas l'effacer,
et le résultat de la rotation dépend d'un composant de Hornn. Contraire à l'esprit de la règle
« les clés ne vivent que dans `hirzla-core` », même si la gateway voit déjà le mot de passe
pendant la session.

## Conséquences
- Tant que l'ADR n'est pas tranché, la rotation est testée de bout en bout contre le faux
  transport et le simulateur de plan de contrôle, mais ne tourne pas en production.
- Le trait ne change pas selon l'option retenue.
- À surveiller : la politique de mots de passe des cibles (longueur, classes), le cas des cibles
  qui exigent un changement par un compte d'administration, et l'épinglage des clés d'hôte.

## Alternatives écartées
- **Pas de rotation** : `roles.md` rappelle que seule la rotation du mot de passe sur la cible
  protège après une révocation ; c'est un objectif de la phase 4.
- **Écrire SSH à la main** : exclu (règle 1).
