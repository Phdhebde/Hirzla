# ADR 0026 — Extension navigateur : geste, cadre principal et vérification de l'origine

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

L'étape 8 livre l'extension (Firefox et Chromium, Manifest V3). Elle doit remplir un
identifiant seulement sur le domaine exact enregistré, jamais dans un cadre d'une autre
origine, jamais sans geste de l'utilisateur, avec des permissions minimales, sans stocker de
secret ni de clé (`PROMPTS.md`, étape 8 ; `modele-de-menace.md`, hameçonnage ; cible de
sécurité, F10 et H7).

L'extension vit à côté du contenu web : c'est la pièce la plus exposée. Le noyau est la seule
pièce de confiance, mais il ne voit pas l'onglet. L'API locale v1 ne permettait au client que
`List` (tout l'index) et `Read` (n'importe quel champ) : un client navigateur aurait pu vider
le coffre, et la comparaison de domaine aurait été faite par le client.

## Décision

1. **Aucun script de contenu, aucun script d'arrière-plan.** Tout part de la fenêtre de
   l'extension (popup), ouverte par l'utilisateur (icône ou raccourci). Permissions :
   `activeTab`, `scripting`, `nativeMessaging`, rien d'autre. Chaque action (remplir, proposer
   l'enregistrement, utiliser un mot de passe généré) demande un clic dans cette fenêtre,
   interface du navigateur qu'une page ne peut ni dessiner ni cliquer.
2. **Cadre principal seulement.** La fonction injectée l'est avec `frameIds: [0]` ; elle
   vérifie être le document de premier niveau (`window.top === window`) de l'origine attendue
   et ne parcourt que ce document. Aucun cadre n'est rempli, même de la même origine.
3. **Champs visibles seulement** : affiché, visible, opacité cumulée ≥ 0,5, au moins
   8 × 8 px, dans la page, non rogné, au premier plan en son centre (son étiquette exceptée),
   actif, modifiable. Le champ d'identifiant n'est rempli que s'il est visible.
4. **Vérification de l'origine à trois niveaux** :
   - **extension** : l'origine vient du navigateur (`tab.url`, accordé par `activeTab`),
     jamais de la page ; elle est relue juste avant chaque injection, et la réponse
     d'injection doit venir du cadre 0 et annoncer cette origine ;
   - **hôte natif** : n'accepte qu'une origine `https` canonique ;
   - **noyau** (API locale v2) : `Match` et `Fill` ne répondent que pour l'hôte **exact** de
     l'origine nommée, en `https`, parmi les `hosts` de l'index ; `Fill` répond `NotFound`
     dans tous les autres cas, sans dire pourquoi. Un **profil navigateur**, décidé par le
     noyau d'après l'exécutable du client (`hirzla-native-host`), interdit à ce client
     `List`, `Read`, `Update`, `Delete`, `Init`, `Unlock` et `Shutdown`, et ne lui permet de
     créer qu'un secret de type mot de passe portant une URL, dans le casier personnel.
5. **Pas de déverrouillage depuis le navigateur** : le mot de passe maître n'y passe jamais.
   Coffre verrouillé : l'extension renvoie vers l'application ou `hirzla unlock`.
6. **`https` seulement, hôte exact, port ignoré** : l'index ne garde que l'hôte
   (`format.md` § 10) ; le garder avec schéma et port demanderait un changement de format.
7. **Enregistrement sur demande** : l'extension lit l'identifiant saisi dans la page quand
   l'utilisateur clique sur « Enregistrer », le montre, et l'enregistre après confirmation,
   sauf s'il existe déjà pour cette origine (pas de remplacement depuis l'extension).
8. **Hôte natif sans état**, lancé par le navigateur pour chaque message ; une connexion au
   noyau par lancement ; il ne se durcit qu'après un `Status` accepté (piège de l'étape 6 :
   un processus non vidable masque son exécutable au noyau sous Linux).

## Conséquences

- Aucune page ne peut parler à l'extension, la détecter ou déclencher un remplissage ; une
  page piégée ne voit rien tant que l'utilisateur n'ouvre pas Hirzla sur elle.
- Une extension ou un hôte compromis ne peut ni lister ni lire le coffre : il doit nommer
  chaque origine et n'obtient que les identifiants exactement enregistrés pour elle. Il peut
  encore, en nommant `https://banque.example`, obtenir l'identifiant de cette banque ; seule
  l'extension lie l'origine à l'onglet. C'est la limite de toute extension de remplissage.
- Pas de remplissage dans les cadres, les *shadow DOM*, les sites en `http` ; pas de
  détection de la soumission d'un formulaire ; pas de mise à jour d'un mot de passe.
- L'API locale passe en version 2 (`docs/api-locale.md`), sans changer les opérations 1 à 11.
- Le profil repose sur le chemin de l'exécutable, avec les limites de la liste d'autorisation
  (`docs/api-locale.md` § 3.3).

## Alternatives écartées

- **Script de contenu sur toutes les pages** (icône dans les champs, détection de
  soumission) : permissions sur tous les sites, surface exposée à chaque page, clics dans la
  page falsifiables (détournement de clic).
- **Script d'arrière-plan** gardant une liste ou un cache : un état à protéger, sans besoin.
- **Comparaison de domaine dans l'extension seulement** : la pièce la plus exposée aurait
  décidé seule, avec un `List` complet entre les mains.
- **Domaine enregistrable (liste des suffixes publics), sous-domaines, « www. »** : contraire
  à l'exigence de domaine exact ; un sous-domaine compromis ou hébergé par un tiers
  recevrait le mot de passe.
- **Remplir les cadres de même origine** : plus pratique, mais le contrôle passe par la page
  ou par `webNavigation` ; écarté pour cette version.
- **Déverrouillage dans la fenêtre de l'extension** : le mot de passe maître traverserait le
  navigateur, dans des chaînes JavaScript impossibles à effacer.
- **Port natif persistant** (`connectNative`) : garderait un hôte et une connexion ouverts
  sans besoin ; un lancement par message suffit.
