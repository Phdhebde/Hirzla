# ADR 0016 — Presse-papiers et saisie au terminal dans la CLI

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

L'étape 6 demande que `hirzla get` écrive sur la sortie standard seulement si elle n'est pas
un terminal ou sur option explicite, et sinon copie le secret dans le presse-papiers avec un
effacement différé. La CLI doit aussi lire le mot de passe maître sans écho. Le
presse-papiers passe par des API natives (Win32, NSPasteboard, X11) : écrire ce code exigerait
du `unsafe` hors de `hirzla-keystore`. Une dépendance qui manipule des secrets et contient du
`unsafe` demande un ADR (`CLAUDE.md`).

## Décision

1. **`arboard` 3.7.0**, sans les fonctionnalités par défaut (`default-features = false`) :
   maintenue par 1Password, MIT ou Apache-2.0, utilisée par de nombreux gestionnaires de mots
   de passe. Elle tire `clipboard-win` et `error-code` (BSL-1.0, ajoutés en exception
   nominative dans `deny.toml`), `x11rb` sous Linux, `objc2*` sous macOS. Pas de
   fonctionnalité Wayland (`wl-clipboard-rs`) ni d'images.
2. **Exclusions** demandées à chaque copie : historique et nuage sous Windows
   (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory`,
   `CanUploadToCloudClipboard`), type « concealed » sous macOS, exclusion des gestionnaires
   d'historique sous Linux quand `arboard` le permet.
3. **Processus auxiliaire détaché** (`hirzla __clipboard SECONDES`) : il reçoit le secret par
   un tube, le dépose, attend le délai (30 s par défaut, ou `clipboard_clear_s` du coffre),
   puis efface le presse-papiers seulement s'il contient toujours ce secret (comparaison en
   temps constant). Sous X11 il faut un processus vivant pour servir la sélection ; c'est le
   même. Il applique le durcissement du noyau (pas de vidage mémoire, pas de traçage).
4. **Saisie sans écho écrite dans `hirzla_keystore::platform`** (termios sous Unix,
   `ReadConsoleW` sous Windows), lue octet par octet dans un `Zeroizing<String>`. Pas de
   dépendance `rpassword`.

Réversible : la CLI ne détient aucune clé, ni le format ni la suite cryptographique ne
changent.

## Conséquences

- Le secret quitte le noyau vers la CLI puis le presse-papiers, comme prévu par l'ADR 0007 ;
  tout processus du même utilisateur peut lire le presse-papiers pendant le délai. C'est une
  limite connue de tous les gestionnaires de mots de passe.
- Wayland pur n'est pas couvert (X11/XWayland seulement) : `--stdout` reste possible.
- Le comportement du presse-papiers doit être vérifié à la main sur chaque système ; les
  tests automatiques passent par `--stdout` ou une sortie non terminal.

## Alternatives écartées

- **Appeler `xclip`, `wl-copy`, `pbcopy`, `clip.exe`** : dépend d'outils absents par défaut,
  le secret transite par un processus tiers, aucune exclusion d'historique sous Windows.
- **Code natif maison** : du `unsafe` dans la CLI, interdit, ou un module presse-papiers dans
  `hirzla-keystore`, qui n'a rien à voir avec le matériel.
- **`copypasta`, `cli-clipboard`** : moins maintenues, pas d'exclusion d'historique.
- **Pas de presse-papiers** : contraire à l'exigence de l'étape 6 (pas de secret affiché sur
  un terminal).
- **`rpassword`** : simple, mais une dépendance de plus qui manipule le mot de passe maître
  dans des `String` non effacées.
