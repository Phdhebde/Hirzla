# Charte Hirzla — l'essentiel pour le code

Référence complète : la charte graphique Hirzla (planches Logo, Couleurs, Typographies, Ton).
Ce dossier en reprend ce qu'il faut pour l'interface.

## Logo « les couches »

Deux anneaux hexagonaux aux ouvertures décalées autour d'un noyau braise : les deux couches
de chiffrement, classique et post-quantique, autour du secret.

| Fichier | Usage |
| --- | --- |
| `logo/hirzla-symbole-fond-sombre.svg` | Version de référence, sur Fonte |
| `logo/hirzla-symbole-fond-clair.svg` | Documents, interfaces claires |
| `logo/hirzla-symbole-monochrome.svg` | Une seule encre, sur Braise |
| `logo/hirzla-symbole-petit-*.svg` | Sous 24 px : un seul anneau, noyau agrandi (icône d'application, favicon) |

Logotype : HIRZLA en capitales, Space Grotesk 600, interlettrage +6 %, à droite du symbole.
Dans une phrase, on écrit « Hirzla ».

Règles : zone de protection d'un quart de la hauteur du symbole ; ne pas faire pivoter les
anneaux ni aligner leurs ouvertures ; pas de dégradé, pas d'ombre ; la braise seulement au centre.

## Couleurs

Variables dans `tokens.css` et `tokens.json`. À retenir :

- Texte sur Braise : toujours en Fonte, jamais en blanc.
- Texte orange sur fond clair : Braise foncée, pas Braise.
- Sur Ardoise, la Braise sert aux formes et aux grands titres, pas au petit texte.
- Un état se reconnaît à sa forme autant qu'à sa couleur : carré (scellé), rond (ouvert), triangle (alerte).

## Typographies

Space Grotesk pour les titres, Inter pour le texte, JetBrains Mono pour toute valeur que l'on
recopie (secrets, empreintes, chemins, commandes). Les trois sont sous licence OFL et doivent
être **embarquées** dans l'application : aucun chargement depuis un CDN.

## Ton

Factuel, sobre, direct, au vouvoiement.

- On écrit : « Le coffre est verrouillé. Trois détenteurs de clé sur cinq doivent le rouvrir. »
- On écrit : « Accès refusé : votre rôle ne couvre pas ce casier. Demandez l'accès à son propriétaire. »
- On n'écrit pas : « sécurité de niveau militaire », « inviolable », « Oups ».
- On n'écrit pas « certifié ANSSI » tant qu'une qualification n'est pas délivrée.
  On écrit « conçu selon les recommandations de l'ANSSI ».

Vocabulaire : un secret est scellé ou descellé ; le coffre est verrouillé ou ouvert ; un accès
temporaire est un bail. Voir `docs/glossaire.md`.
