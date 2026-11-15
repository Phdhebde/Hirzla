# Extension navigateur

Extension Firefox et Chromium (Chrome, Edge, Brave…), Manifest V3, reliée au noyau par
messagerie native. Elle remplit un identifiant **seulement** sur le domaine exact enregistré
avec lui, **seulement** dans le document principal de la page, **seulement** quand vous le
demandez. Elle ne stocke aucun secret et aucune clé. Décisions : ADR 0026 (architecture et
vérification de l'origine) et ADR 0027 (encodage JSON de l'hôte), tous deux proposés.

```text
page web ─(rien : ni script de contenu, ni message)─ extension
                                                     │ clic dans la fenêtre Hirzla
                                                     │ (activeTab, scripting)
extension ─ messagerie native (JSON) ─ hirzla-native-host ─ API locale v2 (CBOR) ─ hirzla-core
                                        profil « navigateur »                       coffre, clés
```

| Élément | Chemin | Rôle | Ce qu'il voit |
| --- | --- | --- | --- |
| Extension | `apps/extension/src` | Fenêtre (popup), injection dans la page à la demande | L'origine de l'onglet ; la liste des identifiants de cette origine (titre, nom d'utilisateur) ; le mot de passe choisi, le temps de le remettre à la page |
| Hôte natif | `apps/native-host` (`hirzla-native-host`) | Traduit le JSON en requêtes de l'API locale | La même chose, le temps d'une requête ; aucune clé, aucun état, aucun journal |
| Noyau | `crates/hirzla-core` | Décide : origine `https` exacte, profil navigateur | Tout le coffre |

## Utilisation

1. Ouvrez le coffre avec l'application ou `hirzla unlock`. L'extension ne l'ouvre pas : le mot
   de passe maître ne passe jamais par le navigateur.
2. Sur la page de connexion, cliquez sur l'icône Hirzla (ou `Alt+Maj+H`). La fenêtre affiche
   l'origine exacte de la page et les identifiants enregistrés pour elle.
3. Cliquez sur un identifiant : il est rempli dans les champs visibles du document principal.
4. **Enregistrer l'identifiant saisi** : après avoir tapé un identifiant dans la page, propose
   de l'enregistrer pour cette origine (titre et nom d'utilisateur modifiables, confirmation).
   Un identifiant existant n'est pas remplacé : modifiez-le dans l'application.
5. **Générateur** : mot de passe tiré par le noyau ; **Utiliser sur cette page** le place dans
   les champs « nouveau mot de passe » visibles (et leur confirmation), puis propose de
   l'enregistrer.
6. **Verrouiller** verrouille le coffre pour tous les clients.

## Règles de remplissage

Un remplissage n'a lieu que si **toutes** ces conditions tiennent ; sinon il est refusé et la
fenêtre dit pourquoi.

| Règle | Où elle est vérifiée |
| --- | --- |
| Geste de l'utilisateur : un clic dans la fenêtre de l'extension, interface du navigateur qu'aucune page ne peut dessiner ni cliquer | Extension (aucun script de contenu, aucun script d'arrière-plan : rien ne s'exécute sans ce clic) |
| La page est servie en `https` | Extension, hôte, noyau |
| L'hôte de la page est **exactement** un hôte enregistré avec le secret (ni sous-domaine, ni domaine parent, ni « www. », ni ressemblance ; forme ASCII IDNA) | Noyau (`Match`, `Fill`, `docs/api-locale.md` § 6.1) |
| L'origine est celle de l'onglet, lue dans le navigateur (`tabs`), jamais dans la page ; elle est relue juste avant chaque injection | Extension |
| Injection dans le cadre principal seulement (`frameIds: [0]`) ; la page confirme être le document de premier niveau de cette origine | Extension, puis la fonction injectée |
| Aucun cadre n'est rempli, même de la même origine | Extension (la fonction injectée ne parcourt que le document principal) |
| Le champ de mot de passe est visible : affiché, `visibility: visible`, opacité cumulée ≥ 0,5, au moins 8 × 8 px, dans la page, non rogné (`clip`, `clip-path`), au premier plan en son centre (seule son étiquette peut le recouvrir), actif et modifiable | Fonction injectée |
| Le champ d'identifiant n'est rempli que s'il est visible, dans le même formulaire, avant le mot de passe | Fonction injectée |

**Pourquoi la vérification d'origine est faite à trois endroits.** Le noyau est le seul
composant de confiance, mais il ne voit pas l'onglet : il ne peut pas savoir quelle page est
affichée. L'extension le sait par le navigateur (hypothèse H7 de la cible de sécurité : le
navigateur ne falsifie pas l'origine de la page), mais elle vit à côté du contenu web et
reste la pièce la plus exposée. Donc :

- l'**extension** lie la demande à l'onglet réel (origine lue par le navigateur, cadre 0) ;
- l'**hôte** refuse toute origine qui n'est pas une origine `https` canonique ;
- le **noyau** ne rend un mot de passe au client navigateur que pour l'origine que celui-ci
  nomme, si elle est enregistrée exactement, et refuse à ce client tout le reste (`List`,
  `Read`, `Update`, `Delete`, `Init`, `Unlock`, `Shutdown`) d'après son exécutable. Une
  extension ou un hôte compromis ne peut donc pas vider le coffre : il doit nommer chaque
  origine, une à une, et ne reçoit rien pour une origine que le coffre ne connaît pas.

## Permissions

Le manifeste (`src/manifest.json`) demande trois permissions, rien d'autre.

| Permission | Pourquoi | Sans elle |
| --- | --- | --- |
| `activeTab` | Donne, **seulement après votre clic** sur l'icône ou le raccourci, l'accès à l'onglet actif : son adresse (pour en tirer l'origine) et le droit d'y injecter du code. Le droit tombe quand l'onglet change d'origine ou se ferme. | Il faudrait `tabs` et des permissions d'hôte sur tous les sites (`<all_urls>`), actives en permanence. |
| `scripting` | Exécuter, dans le cadre principal de cet onglet, la fonction qui vérifie les champs, remplit ou lit l'identifiant saisi (`src/lib/page.js`). | Il faudrait un script de contenu injecté dans toutes les pages, en permanence. |
| `nativeMessaging` | Parler à `hirzla-native-host`, seul chemin vers le noyau. | L'extension ne peut rien faire. |

Volontairement absents :

- **Permissions d'hôte** (`host_permissions`, `<all_urls>`) et **scripts de contenu** : aucune
  page ne voit l'extension, aucune ne peut lui parler ni déclencher un remplissage.
- **`tabs`** : `activeTab` suffit, et seulement pour l'onglet choisi.
- **`storage`**, **`unlimitedStorage`** : rien n'est conservé par l'extension, pas même une
  liste de sites.
- **`clipboardWrite`** : pas de presse-papiers ; le mot de passe va directement dans le champ.
- **`webRequest`**, **`webNavigation`**, **`cookies`**, **`history`**, **`notifications`**,
  **`contextMenus`**, **`alarms`**, **`identity`** : sans usage.
- **`background`** (script d'arrière-plan) : aucun état, aucune écoute ; tout part de la
  fenêtre.
- **`externally_connectable`**, **`web_accessible_resources`** : aucun site ni autre
  extension ne peut lui envoyer de message ni charger ses fichiers (pas de détection de
  l'extension par une page).

`commands` (raccourci `Alt+Maj+H`, modifiable dans le navigateur) n'est pas une permission :
il ouvre la même fenêtre que l'icône et donne le même `activeTab`.

**Politique de sécurité du contenu** des pages de l'extension :
`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'`.
Aucune ressource distante, aucun script en ligne, aucun `eval`. Les textes venant d'une page,
de l'hôte ou du coffre sont posés avec `textContent`, jamais interprétés comme du HTML.

## Protocole de l'hôte

Messagerie native : chaque message est une longueur sur 32 bits (ordre natif) suivie d'un
objet JSON en UTF-8. Le navigateur lance `hirzla-native-host` pour chaque message de
l'extension (`runtime.sendNativeMessage`). L'hôte accepte au plus 64 Kio par message et
répond au plus 1 Mio (limite des navigateurs). JSON accepté : un objet plat dont les membres
sont des chaînes, des booléens ou des entiers positifs ; clé inconnue, en double, ou valeur
d'un autre type : `bad_request` (ADR 0027).

| Requête | Réponse | Requête(s) au noyau |
| --- | --- | --- |
| `{"type":"status"}` | `{"ok":true,"state":"absent"\|"locked"\|"unlocked"}` | `Status` |
| `{"type":"match","origin":O}` | `{"ok":true,"entries":[{"locker","id","title","username"?}],"truncated":bool}` | `Match` |
| `{"type":"fill","origin":O,"locker":L,"id":I}` | `{"ok":true,"username"?,"password"}` | `Fill` |
| `{"type":"save","origin":O,"password":P,"username"?,"title"?}` | `{"ok":true}` | `Create` (type mot de passe, URL = `O`, casier personnel, titre par défaut : l'hôte) |
| `{"type":"generate","length"?:8..128,"symbols"?:bool}` | `{"ok":true,"password"}` | `Generate` (20 caractères, toutes classes par défaut) |
| `{"type":"lock"}` | `{"ok":true}` | `Lock` |

`O` est une origine `https` canonique (`https://hôte[:port]`) ; `L` et `I` sont 32 chiffres
hexadécimaux minuscules. Refus : `{"ok":false,"error":CODE}`, où `CODE` est un code de
l'hôte (`bad_request`, `invalid_origin`, `invalid_input`, `core_not_running`,
`untrusted_core`, `core_error`, `too_large`) ou le nom d'une erreur du noyau
(`docs/api-locale.md` § 7 : `locked`, `no_vault`, `not_found`, `unauthorized`…). Un refus ne
contient jamais de détail.

Les chaînes écrites par l'hôte échappent aussi `<`, `>`, `&`, U+2028 et U+2029.

## Installation

Les exécutables `hirzla-core` et `hirzla-native-host` doivent être **dans le même
répertoire** : le noyau n'accepte l'hôte qu'à côté de lui, avec le profil navigateur, et
l'hôte ne parle qu'au noyau situé à côté de lui (`docs/api-locale.md` § 3).

### 1. L'extension

- **Chromium, Chrome, Edge, Brave** : `chrome://extensions` → mode développeur → « Charger
  l'extension non empaquetée » → `apps/extension/src`. Notez l'**identifiant** affiché
  (32 lettres) : il entre dans le manifeste de l'hôte. Une extension non empaquetée a un
  identifiant dérivé de son chemin ; la version publiée aura un identifiant fixe. Chrome
  signale la clé `browser_specific_settings` (propre à Firefox) comme inconnue : sans effet.
- **Firefox** (128 ou plus) : `about:debugging` → « Ce Firefox » → « Charger un module
  complémentaire temporaire » → `apps/extension/src/manifest.json`. L'identifiant est fixe :
  `extension@hirzla.invalid`. Une installation durable demande un paquet signé
  (livraison, étape 7).

### 2. Le manifeste de l'hôte

Partez de `native-host-manifests/chromium.json` (Chromium et dérivés) ou
`native-host-manifests/firefox.json` (Firefox). Remplacez `path` par le **chemin absolu** de
`hirzla-native-host` (`hirzla-native-host.exe` sous Windows) et, pour Chromium,
`IDENTIFIANT_DE_L_EXTENSION` par l'identifiant noté. Le fichier s'appelle
`hirzla.native_host.json`. Le nom `hirzla.native_host` ne doit pas changer : c'est celui que
l'extension appelle.

**Linux** — copiez le fichier dans le répertoire du navigateur (par utilisateur ; entre
parenthèses, pour tout le poste) :

| Navigateur | Répertoire |
| --- | --- |
| Chrome | `~/.config/google-chrome/NativeMessagingHosts/` (`/etc/opt/chrome/native-messaging-hosts/`) |
| Chromium | `~/.config/chromium/NativeMessagingHosts/` (`/etc/chromium/native-messaging-hosts/`) |
| Edge | `~/.config/microsoft-edge/NativeMessagingHosts/` (`/etc/opt/edge/native-messaging-hosts/`) |
| Brave | `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/` |
| Firefox | `~/.mozilla/native-messaging-hosts/` (`/usr/lib/mozilla/native-messaging-hosts/` ou `/usr/lib64/mozilla/native-messaging-hosts/`) |

Un navigateur lancé avec `--user-data-dir=REP` cherche aussi dans `REP/NativeMessagingHosts/`
(c'est ce qu'utilisent les tests). Les navigateurs en **Snap** ou **Flatpak** sont isolés :
Chromium en Snap ou Flatpak ne peut pas lancer d'hôte natif ; Firefox en Snap passe, selon
les versions, par le portail XDG (`webextensions`), qui demande votre accord au premier
lancement. Préférez un
navigateur installé par le paquet du système.

**macOS** :

| Navigateur | Répertoire (par utilisateur ; pour tout le poste) |
| --- | --- |
| Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` ; `/Library/Google/Chrome/NativeMessagingHosts/` |
| Chromium | `~/Library/Application Support/Chromium/NativeMessagingHosts/` ; `/Library/Application Support/Chromium/NativeMessagingHosts/` |
| Edge | `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/` ; `/Library/Microsoft/Edge/NativeMessagingHosts/` |
| Brave | `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/` |
| Firefox | `~/Library/Application Support/Mozilla/NativeMessagingHosts/` ; `/Library/Application Support/Mozilla/NativeMessagingHosts/` |

**Windows** — placez le fichier où vous voulez (par exemple à côté de
`hirzla-native-host.exe` ; `path` peut alors être relatif au manifeste), puis créez la clé de
registre dont la **valeur par défaut** est le chemin complet du manifeste. Par utilisateur
sous `HKEY_CURRENT_USER`, pour tout le poste sous `HKEY_LOCAL_MACHINE` :

| Navigateur | Clé |
| --- | --- |
| Chrome | `HKCU\Software\Google\Chrome\NativeMessagingHosts\hirzla.native_host` |
| Chromium | `HKCU\Software\Chromium\NativeMessagingHosts\hirzla.native_host` |
| Edge | `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\hirzla.native_host` |
| Brave | `HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\hirzla.native_host` |
| Firefox | `HKCU\Software\Mozilla\NativeMessagingHosts\hirzla.native_host` |

```bat
reg add "HKCU\Software\Google\Chrome\NativeMessagingHosts\hirzla.native_host" /ve /t REG_SZ /d "C:\Program Files\Hirzla\hirzla.native_host.json" /f
```

Sous Windows 64 bits, les navigateurs consultent les deux vues du registre (64 et 32 bits,
`WOW6432Node`) : une clé dans l'une suffit. L'installateur de l'étape 7 écrira ces clés et fichiers ; d'ici là,
l'installation est manuelle.

### 3. Vérifier

Ouvrez le coffre (`hirzla unlock`), allez sur une page `https` dont l'identifiant est
enregistré avec son URL (`hirzla set NOM --url https://…`), cliquez sur l'icône Hirzla.
« L'hôte Hirzla n'est pas installé » : le manifeste n'est pas trouvé, ou l'identifiant de
l'extension ne correspond pas. « Le noyau n'est pas démarré » : `hirzla unlock` le démarre.
« Accès refusé » côté noyau (`unauthorized`) : l'hôte n'est pas à côté du noyau.

## Tests

```sh
cd apps/extension
npm test                       # unités (node --test) : origine, décisions
cargo build -p hirzla-core -p hirzla-cli -p hirzla-native-host
npm ci && npx playwright install chromium
npm run test:e2e               # Chromium réel, hôte réel, noyau réel
```

Côté Rust : `cargo test -p hirzla-native-host` (JSON, traduction, refus ; bout en bout contre
un vrai noyau) et `cargo test -p hirzla-core` (`Match`, `Fill`, profil navigateur).

Les tests de bout en bout chargent l'extension dans Chromium (Playwright, nouveau mode sans
interface), installent le manifeste de l'hôte dans le profil de test, démarrent un vrai
`hirzla-core` avec un coffre créé par `hirzla`, et servent les pages de `tests/pages/` sous des
origines fictives `*.test`. Chacun de ces cas **refuse** le remplissage et laisse les champs
vides :

| Cas | Page | Refus |
| --- | --- | --- |
| Domaine ressemblant : trait d'union, lettre, homographe IDN (`bаnk.test` cyrillique), nom enregistré en sous-domaine d'un autre | `login.html` sous `bank-test.test`, `banq.test`, `xn--bnk-6cd.test`, `bank.test.evil.test` | Liste vide ; `Fill` forcé : `not_found` (noyau) |
| Sous-domaine, domaine parent | `login.bank.test`, `test` | Idem |
| `http` | `http://bank.test/login` | `unsupported_page` (extension), `invalid_origin` (hôte) |
| Cadre tiers : page tierce qui encadre la vraie page de connexion | `evil-embeds-bank.html` | Aucun identifiant pour l'origine ; rien dans le cadre |
| Cadre tiers : page enregistrée dont le champ est dans un cadre d'une autre origine | `bank-embeds-evil.html` | `no_field` ; rien dans le cadre |
| Champ caché : `display`, `visibility`, opacité nulle ou faible, hors page, 1 px, `clip-path`, parent masqué ou transparent, recouvert | `hidden.html` (10 variantes) | `hidden` |
| Leurres cachés autour d'un formulaire visible | `decoy.html` | Seuls les champs visibles sont remplis |

S'y ajoutent : remplissage réussi sur l'origine exacte, générateur puis proposition
d'enregistrement (une seule fois), refus des opérations hors profil, coffre verrouillé, et
l'absence de secret et de site visité dans le journal du noyau.

**Ce qui n'a pas pu tourner** : Firefox. Playwright ne charge pas d'extension dans Firefox et
aucun Firefox n'est installé dans l'environnement de test. Le code n'utilise que des API
communes aux deux (`activeTab`, `scripting.executeScript` avec `func` et `args`,
`runtime.sendNativeMessage`, `tabs.query`/`tabs.get`), via `browser` s'il existe, `chrome`
sinon ; à vérifier à la main avec `about:debugging` avant la livraison. Le geste de
l'utilisateur (clic sur l'icône, qui accorde `activeTab`) ne peut pas être simulé : les tests
donnent à la copie de test des permissions d'hôte sur `*.test` et appellent les mêmes
fonctions que la fenêtre (`src/lib/actions.js`).

## Limites connues

- Pas de remplissage dans un cadre, même de la même origine, ni dans un *shadow DOM*.
- Pas de remplissage d'un site en `http`, ni de distinction par port : l'index du coffre ne
  garde que l'hôte (`docs/api-locale.md` § 13).
- Pas de détection automatique de la soumission d'un formulaire : l'enregistrement se propose
  sur demande (il faudrait sinon un script de contenu sur toutes les pages).
- Pas de mise à jour d'un mot de passe existant depuis l'extension (application ou CLI).
- Le mot de passe rempli passe par le processus de la page, comme pour tout gestionnaire :
  une page de l'origine enregistrée peut le lire ; c'est le site auquel il appartient.
- En JavaScript, une chaîne ne peut pas être effacée : le mot de passe reçu de l'hôte reste
  en mémoire de la fenêtre de l'extension jusqu'à sa fermeture (qui suit le remplissage).
