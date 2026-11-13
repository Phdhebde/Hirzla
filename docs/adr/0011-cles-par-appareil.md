# ADR 0011 — Clés par appareil, certifiées par la clé du membre

- Statut : accepté sur le principe (2026-11-13) ; détails ci-dessous à relire
- Date : 2026-11-13

## Contexte

Dans la v1 des spécifications, tous les appareils d'un membre partageaient ses paires
hybrides (ADR 0006, `crypto.md`). Un appareil volé détenait donc tout ce qu'il fallait pour
signer et lire au nom du membre. Le retirer obligeait à faire tourner les clés du membre et à
le réinscrire dans chaque casier.

Le modèle de menace demande au contraire de « révoquer l'appareil ».

## Décision

1. **Chaque appareil a ses propres paires hybrides** : une paire de signature
   (ECDSA P-384 + ML-DSA-87) et une paire d'établissement de clé (ECDH P-384 + ML-KEM-1024).
   Elles sont tirées sur l'appareil. Leur partie privée ne le quitte jamais et est scellée par
   la clé du poste.
2. **La clé du membre devient une racine de certification** : une paire de signature hybride
   qui ne sert qu'à signer des **certificats d'appareil** et des **révocations d'appareil**.
   C'est elle qui identifie le membre, au registre de transparence et, d'ici là, par
   confiance au premier contact avec vérification d'empreinte hors bande.
3. **La clé privée du membre ne réside que sur les appareils de certification** : ceux que
   l'utilisateur désigne (par défaut, le premier appareil), plus le mécanisme de récupération
   (`roles.md`). Un appareil ordinaire n'a que ses propres clés.
4. **Tout ce qu'un appareil signe l'est avec sa clé d'appareil** : opérations, accords de
   validation à plusieurs, authentification auprès du serveur et des autres appareils.
5. **La clé de casier est enveloppée pour chaque appareil** non révoqué de chaque lecteur.
6. **Retirer un appareil** : une révocation signée par la clé du membre est publiée dans
   chaque casier du membre, avec une rotation de la clé du casier. Les autres appareils du
   membre ne sont pas touchés. Une révocation est définitive.

Les structures sont dans `docs/format.md` (§ 3) et la sémantique dans `docs/sync-protocol.md`
(§ 7 et § 9.7).

## Conséquences

- Un appareil volé se retire seul, sans toucher aux autres appareils du membre ni à son
  identité. La rotation de la clé de casier qui accompagne le retrait lui coupe la lecture
  des nouvelles versions.
- Une bifurcation de chaîne désigne un appareil précis.
- Il y a plus d'enveloppes : une par appareil de lecteur, environ 1,7 ko chacune. Un casier
  de 50 membres à 3 appareils coûte environ 255 ko par rotation.
- Ajouter un appareil demande un appareil de certification, ou la récupération.
- Un nouvel appareil n'a pas d'enveloppe dans les casiers existants. Un autre appareil du
  membre, ou un éditeur du casier, la lui ajoute.
- Le vol d'un appareil de certification déverrouillé permet de certifier des appareils
  pirates. La parade est la rotation de la clé du membre, réservée à l'étape 10 avec la
  récupération. Il faut limiter le nombre d'appareils de certification.
- La hiérarchie de `docs/crypto.md` gagne un niveau.

## Alternatives écartées

- **Clés du membre partagées entre appareils** (v1 des spécifications) : retrait d'un
  appareil coûteux et grossier.
- **Clés de signature par appareil, clé d'établissement partagée** : un appareil retiré ne
  signe plus, mais lit encore les époques suivantes tant que la clé du membre ne tourne pas.
- **Chaîne de signatures entre appareils, sans clé de membre** (chaque appareil certifie le
  suivant) : pas de racine stable pour le registre de transparence, et un appareil volé
  peut révoquer tous les autres.
