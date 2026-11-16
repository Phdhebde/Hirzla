# Plan de tests manuels avant la version 1

Pour l'éditeur, à dérouler sur de **vraies machines** avec les installeurs de la version
candidate (flux *Livraison*, signés comme au `docs/guide-signature.md` § 7), avant de publier la
version 1. Les tests automatiques (CI sur les trois systèmes) couvrent le code ; ce plan couvre
ce qu'ils ne voient pas : installeurs, système réel, navigateur réel, deux postes et un serveur.

Chaque ligne donne les **étapes**, puis le **résultat attendu** après « → ». Cochez une ligne
quand le résultat est celui attendu ; sinon, notez l'écart (§ 8). Le guide d'installation de
référence est `docs/installation.md`.

## 0. Préparation

- [ ] Machines : un Windows 11 (et si possible un Windows 10 à jour), un Mac Apple silicon,
      un Linux Debian ou Ubuntu, un Linux Fedora. Chacune **sans** ancienne installation de
      Hirzla (pas de `coffre.hirzla` aux emplacements du `installation.md` § 6).
- [ ] Un serveur `hirzlad` installé selon `guide-agd.md` § 5.1, joignable par deux postes,
      avec deux comptes de membres (§ 8).
- [ ] Fichiers de la version téléchargés depuis la page *Releases* (brouillon) :
      installeurs, `SHA256SUMS`, `SHA256SUMS.asc`, `hirzla-clients.manifest`.
- [ ] Vérification des téléchargements (`installation.md` § 2) : `gpg --verify SHA256SUMS.asc
      SHA256SUMS` → bonne signature, empreinte de la clé égale à celle de `SECURITY.md` ;
      `sha256sum -c --ignore-missing SHA256SUMS` → `OK` partout ;
      `gh attestation verify FICHIER --repo Phdhebde/Hirzla` → « Verification succeeded! »
      pour chaque installeur.
- [ ] Une base KeePass KDBX 4 de test (quelques entrées, un groupe, une entrée à la corbeille),
      protégée par un mot de passe seul.

## 1. Commun à tous les systèmes

À dérouler sur **chaque** système, après l'installation propre à ce système (§ 2 à § 4).

### 1.1 Premier démarrage hors ligne

- [ ] Débranchez le réseau (câble, Wi-Fi coupé). Lancez Hirzla → l'écran « Créer votre
      coffre » s'affiche, sans message d'erreur réseau ni attente.
- [ ] Mot de passe maître de 11 caractères → refusé (au moins 12). Mot de passe de 16
      caractères, confirmation différente → refusé.
- [ ] Mot de passe valide, **Créer le coffre** → coffre ouvert en quelques secondes ;
      `coffre.hirzla` créé à l'emplacement du `installation.md` § 6.
- [ ] Pendant tout le § 1, aucune connexion sortante (moniteur réseau du système, ou
      `ss -tp` / `lsof -i` / `Get-NetTCPConnection`) → aucune connexion de `hirzla-core`,
      `hirzla-desktop`, `hirzla`.
- [ ] **Réglages › Protection des processus** → mesures « appliqué » pour le noyau et
      l'application ; sous Linux, `hirzla status` montre « Traçage interdit : appliqué ».

### 1.2 Secrets, verrouillage, presse-papiers

- [ ] **Nouveau secret** (mot de passe, titre, identifiant, URL `https://exemple.fr`),
      **Enregistrer** → listé ; **Verrouiller** puis **Ouvrir** avec le mot de passe → le secret
      est là.
- [ ] Mauvais mot de passe plusieurs fois de suite → « déverrouillage refusé », puis un délai
      croissant est imposé avant le prochain essai ; le bon mot de passe après le délai → ouvert.
- [ ] **Réglages › Coffre** : verrouillage automatique 30 s, **Enregistrer les réglages** ; ne
      touchez à rien pendant 40 s → écran « Le coffre est verrouillé. ».
- [ ] Cases « à la mise en veille du poste » et « au verrouillage de votre session » cochées ;
      verrouillez la session (Windows+L, Ctrl+Cmd+Q, verrouillage du bureau Linux), revenez →
      coffre verrouillé. Même essai avec une mise en veille → coffre verrouillé.
- [ ] Effacement du presse-papiers réglé à 10 s ; copiez le mot de passe du secret, collez-le
      aussitôt dans un éditeur → la valeur est collée ; attendez 15 s, collez de nouveau → plus
      rien (ou l'ancien contenu du presse-papiers).
- [ ] Même essai en ligne de commande : `hirzla get NOM` → « copié », effacé après le délai ;
      `hirzla get NOM | cat` → la valeur sort sur la sortie standard, rien dans le
      presse-papiers.
- [ ] Fermez l'application, rouvrez-la → coffre verrouillé.

### 1.3 Import KeePass

- [ ] **Réglages › Importer › Importer depuis KeePass (KDBX)…**, base de test, son mot de
      passe → toutes les entrées hors corbeille importées dans le casier personnel ; le nombre
      d'entrées de la corbeille KeePass ignorées est annoncé.
- [ ] Mauvais mot de passe de la base → refus, rien d'importé. Base KDBX 3 ou avec fichier
      clé → refus avant tout calcul long.
- [ ] `hirzla import-kdbx BASE.kdbx` sur un autre coffre → même résultat.

### 1.4 Kit de recouvrement

- [ ] **Réglages › Kit de recouvrement**, 3 parts, 2 nécessaires, **Créer le kit…**, dossier
      sur une clé USB → trois fichiers de parts ; l'état du kit l'annonce.
- [ ] Verrouillez ; **Mot de passe perdu ? Ouvrir avec le kit de recouvrement**, choisissez
      **une** part → refus. Deux parts → nouveau mot de passe demandé, coffre ouvert ;
      l'ancien mot de passe n'ouvre plus le coffre, le nouveau oui.
- [ ] Une part d'un autre coffre mêlée à une bonne → refus.
- [ ] **Retirer le kit** → les anciennes parts n'ouvrent plus le coffre.

### 1.5 Extension de navigateur

Installation selon `installation.md` § 7, une fois pour **Firefox** et une fois pour **Chrome**
(ou Chromium) ; coffre ouvert ; un secret enregistré avec l'URL d'un site `https` réel dont
vous avez un compte de test.

- [ ] Page de connexion du site, clic sur l'icône Hirzla → la fenêtre affiche l'origine exacte
      et l'identifiant ; clic sur l'identifiant → identifiant et mot de passe remplis.
- [ ] `Alt+Maj+H` sur la même page → même fenêtre.
- [ ] Sous-domaine ou domaine voisin du site (par exemple `www.` ajouté ou retiré s'il n'est
      pas enregistré) → aucun identifiant proposé.
- [ ] Page en `http` → « Hirzla ne remplit que les pages servies en https. »
- [ ] Coffre verrouillé → la fenêtre le dit ; rien n'est rempli.
- [ ] **Générateur › Utiliser sur cette page** sur un formulaire de création de compte → le
      mot de passe va dans les champs « nouveau mot de passe », puis l'enregistrement est
      proposé une fois.
- [ ] Manifeste de l'hôte absent ou identifiant d'extension faux → « L'hôte Hirzla n'est pas
      installé ».

### 1.6 Signature des clients

- [ ] Journal du noyau (lancez `hirzla-core` dans un terminal, ou consultez la sortie d'erreur
      de son service) → `event=client_signatures required=1 kind=manifeste`.
- [ ] Remplacez l'exécutable `hirzla` installé par un autre `hirzla` (par exemple une
      compilation de développement de la même étiquette, sans la fonctionnalité `livraison`) ;
      `hirzla status` → « accès refusé : ce programme n'est pas autorisé à parler au noyau. » ;
      journal du noyau : `signature_not_accepted`.
- [ ] Remettez l'exécutable d'origine, remplacez `hirzla-core` par un autre noyau ;
      `hirzla status` → « la signature du noyau n'est pas reconnue… », rien n'est envoyé.
- [ ] Altérez un octet de `hirzla-clients.manifest` (copie de sauvegarde avant) → le noyau
      refuse de démarrer. Remettez le manifeste d'origine (ou réinstallez) → tout refonctionne.

### 1.7 Mise à jour hors ligne

Avec un paquet `.hirzla-maj` d'une version **supérieure** signé sur le poste de signature
(`livraison.md` § 8), et un paquet de la **même** version.

- [ ] `hirzla mise-a-jour verifier PAQUET` → contenu affiché (version, plateforme, fichiers).
- [ ] Un octet du paquet altéré → `verifier` refuse.
- [ ] Application et noyau arrêtés (`hirzla stop`), `hirzla mise-a-jour appliquer PAQUET` avec
      les droits d'administrateur → appliqué ; **Réglages** montre les nouvelles versions du
      noyau et de l'application ; le coffre s'ouvre.
- [ ] Paquet de version égale ou inférieure → refusé, rien n'est modifié.
- [ ] Paquet d'une autre plateforme → refusé.

### 1.8 Désinstallation

- [ ] Désinstallez (`installation.md`, section du système) → exécutables, raccourcis et
      manifeste retirés ; `coffre.hirzla` et `coffre.hirzla.serveur` **conservés**.
- [ ] Réinstallez → le coffre existant s'ouvre avec son mot de passe.

## 2. Windows

- [ ] MSI non signé : SmartScreen « Windows a protégé votre ordinateur » → **Informations
      complémentaires › Exécuter quand même** → installation dans `C:\Program Files\Hirzla\`
      avec `hirzla-desktop.exe`, `hirzla-core.exe`, `hirzla.exe`, `hirzla-native-host.exe` et
      `hirzla-clients.manifest` dans ce même dossier.
- [ ] Compte utilisateur standard (non administrateur) → l'application et `hirzla` fonctionnent.
- [ ] Le dossier `C:\Program Files\Hirzla\` n'est pas modifiable sans élévation.
- [ ] Poste sans WebView2 (Windows 10 non à jour), si disponible → aucun téléchargement tenté ;
      noter le message affiché.
- [ ] Dérouler le § 1.
- [ ] Garde matérielle (prototypes, hors produit, ne bloque pas la V1) : tests W1, W2 et W3 de
      `docs/keystore-prototypes.md` sur un PC avec TPM 2.0 → sorties à rapporter. Windows Hello
      n'est pas un mode de déverrouillage de la V1 : vérifiez seulement qu'aucun écran ne le
      propose.

## 3. macOS

- [ ] Paquet `.pkg` signé ad hoc : premier essai refusé → **Réglages Système › Confidentialité
      et sécurité › Ouvrir quand même**, mot de passe de session → installation de
      `/Applications/Hirzla.app` et du manifeste à l'emplacement de l'ADR 0065.
- [ ] Premier lancement de Hirzla → au plus une approbation de plus, puis plus jamais.
- [ ] `codesign -d --entitlements - /Applications/Hirzla.app/Contents/MacOS/hirzla-core` →
      aucun `get-task-allow`.
- [ ] `hirzla-desktop` est bien vérifié par le noyau (journal sans `signature_not_accepted`
      pour l'application) : c'est l'objet de l'ADR 0065.
- [ ] Dérouler le § 1.
- [ ] Garde matérielle (prototype, hors produit) : test M1 de `docs/keystore-prototypes.md` →
      sortie, modèle du Mac et version de macOS à rapporter. Touch ID n'est pas un mode de
      déverrouillage de la V1.

## 4. Linux

- [ ] **deb** : `sudo apt install ./Hirzla_<version>_amd64.deb` → dépendances tirées du dépôt,
      exécutables et manifeste dans `/usr/bin`, propriété de root.
- [ ] **rpm** : `rpm -K` → signatures correctes (si le paquet est signé) ;
      `sudo dnf install ./Hirzla-<version>-1.x86_64.rpm` → idem.
- [ ] **AppImage** : `chmod +x`, lancement → l'application démarre ; le noyau embarqué est
      utilisé.
- [ ] Unité systemd utilisateur du `guide-agd.md` § 2 → `hirzla status` : « Mémoire
      verrouillée : appliqué ». Sans elle → avertissement et `event=memory_not_locked` au
      journal.
- [ ] Session GNOME puis KDE (si possible) : verrouillage à la veille et au verrouillage de
      session (§ 1.2).
- [ ] Firefox et Chrome installés par le paquet de la distribution (pas en Snap ni Flatpak)
      pour le § 1.5 ; un essai avec Firefox en Snap → noter le comportement.
- [ ] Dérouler le § 1 (sur Debian ou Ubuntu en entier ; sur Fedora au moins § 1.1, § 1.2,
      § 1.6 et § 1.8).
- [ ] Garde matérielle (prototype, hors produit) : test L1 de `docs/keystore-prototypes.md` sur
      une vraie puce TPM 2.0 → 5 tests réussis, sortie à rapporter. Aucune clé FIDO2 n'est
      prise en charge en V1 (ADR 0014 : place définie, non implémentée).

## 5. Mode Serveur, deux postes

Deux postes A (membre Alice) et B (membre Bob), de systèmes différents si possible, et le
serveur du § 0. Coffres neufs.

### 5.1 Rattachement

- [ ] Sur A et B : **Serveur › Votre identité › Enregistrer votre clé publique…** → fichier à
      remettre ; l'administrateur crée les deux comptes après avoir comparé les empreintes lues
      de vive voix.
- [ ] L'administrateur produit le lien (`hirzlad invitation …`). Sur A : **Rejoindre avec le
      lien** → « Serveur rattaché par le lien d'invitation, empreinte vérifiée. Le serveur
      reconnaît votre compte. »
- [ ] Lien altéré (un caractère changé) → refusé, rien n'est envoyé au serveur.
- [ ] Sur B, sans lien : adresse, fichier PEM, empreinte vide → écran « Confirmer l'empreinte
      du serveur » ; une empreinte fausse recopiée → refus ; la bonne → rattaché.
- [ ] Empreinte fausse donnée d'emblée (`hirzla serveur rejoindre … --empreinte FAUSSE`) →
      session coupée avant toute authentification.

### 5.2 Casier partagé et rôles

- [ ] Sur A : **Nouveau casier partagé…** « Essais » ; **Membres › Ajouter un membre** Bob,
      rôle lecteur → « L'attribution est signée par ce poste et envoyée au serveur ». Sur B,
      **Synchroniser** → le casier apparaît, rôle lecteur.
- [ ] A crée un secret dans « Essais », synchronise ; B synchronise → B lit le secret. B essaie
      de le modifier → refus (lecteur).
- [ ] A passe Bob en éditeur ; B modifie le secret, synchronise ; A synchronise → A voit la
      nouvelle version et l'historique.
- [ ] Hors ligne : A et B modifient le même secret chacun de son côté, puis synchronisent →
      fusion sans perte (les deux versions dans l'historique, une seule courante, identique
      sur A et B).
- [ ] A retire Bob (**Retirer**) → « Membre retiré. La clé du casier a tourné. » ; A écrit un
      nouveau secret ; B synchronise → « Accès perdu » ; B ne lit pas le nouveau secret.

### 5.3 Quorum

Avec un troisième membre Carol (poste C, ou un troisième coffre sur A) propriétaire.

- [ ] A (propriétaire le plus ancien) donne le rôle propriétaire à Bob puis à Carol ; Carol
      essaie de retirer A → « Ce propriétaire est plus ancien que vous : le retirer exige
      l'accord d'autres propriétaires. »
- [ ] Carol **Demander l'accord pour le retirer…** → demande `hirzla-demande:…` à copier ; Bob
      la colle dans **Signer une demande reçue…**, **Examiner** puis **Signer** → accord
      `hirzla-accord:…` ; Carol **Ajouter l'accord** → « Quorum atteint » ; **Appliquer** →
      A retiré, la clé du casier tourne.
- [ ] Accord altéré, ou signé pour une autre demande → refusé.
- [ ] **Changer le quorum…** à 3 → la demande exige le quorum en vigueur, puis le nouveau
      s'applique.

### 5.4 Quarantaine

- [ ] Bob éditeur ; B hors ligne modifie un secret pendant que A (propriétaire) retire Bob ;
      B se reconnecte et synchronise ; A synchronise → la modification de B apparaît dans
      **Quarantaine** du casier, avec auteur et appareil.
- [ ] A coche la ligne, **Rejeter** → la modification n'est pas appliquée, sur A et sur tout
      autre poste après synchronisation. Variante : **Accepter** → appliquée.
- [ ] Sans décision, après le délai de rejet automatique → rejetée d'elle-même.
- [ ] Pour un propriétaire, la ligne propose **Retirer ce membre du casier**, jamais pour
      soi-même.

### 5.5 Registre des clés et révocation de son propre appareil

L'enrôlement d'un second appareil n'est pas spécifié en V1 (`api-locale.md` § 15.7) : l'alerte
2 « appareil inconnu inscrit à votre nom » ne peut pas être produite sur de vraies machines
sans outil de test. Le chemin complet est couvert par les tests automatiques
`an_unknown_device_is_revoked_from_its_alert` et
`an_own_revocation_read_after_a_restart_raises_no_alert` (`crates/hirzla-core/tests/server_mode.rs`).
À vérifier à la main :

- [ ] Carte **Registre de transparence des clés** → état sain, aucune alerte, sur A et B.
- [ ] `hirzla appareil revoquer 00000000000000000000000000000000 --oui` → « appareil
      introuvable sur ce poste… », rien n'est signé.
- [ ] `hirzla appareil revoquer` avec l'identifiant de l'appareil du poste (lu dans **Votre
      identité**) → refus.
- [ ] Sans terminal (`… < /dev/null`) et sans `--oui` → la confirmation est exigée.
- [ ] Restauration du serveur depuis une ancienne sauvegarde de son répertoire de données,
      puis redémarrage du noyau de A et synchronisation → « Registre suspect : partage
      suspendu » ; création de casier et ajout de membre refusés ; lecture et écriture locales
      toujours possibles.

### 5.6 Réseau

- [ ] Serveur arrêté → **Synchroniser** : « Serveur injoignable » ; le casier reste lisible et
      modifiable sur le poste ; au retour du serveur, les modifications partent.
- [ ] Synchronisation automatique « Toutes les minutes » → aucune connexion vers un autre hôte
      que le serveur rattaché (moniteur réseau).

## 6. Accessibilité et textes

- [ ] Parcours du § 1.1 et du § 1.2 au clavier seul (Tab, Entrée, Échap) → tout est
      atteignable, le focus est visible.
- [ ] Thème clair, sombre, et celui du système → lisible.
- [ ] Textes : vouvoiement, vocabulaire du glossaire (scellé/descellé, verrouillé/ouvert,
      casier) ; aucune faute ni texte anglais visible.

## 7. Ce qui ne bloque pas la V1

Les prototypes de garde matérielle (§ 2, § 3, § 4) informent les choix de la version suivante :
leur échec ne bloque pas la publication. Tout autre écart bloque, sauf décision contraire de
l'éditeur notée dans le rapport.

## 8. Ce qu'il faut rapporter

Pour chaque machine, dans un ticket privé ou dans le fil, **sans aucun mot de passe ni part
de kit** :

1. Système et version exacte (`winver`, `sw_vers`, `/etc/os-release`), modèle de la machine,
   navigateurs et versions.
2. Version de Hirzla (**Réglages** : versions du noyau et de l'application) et fichier
   installé.
3. La liste des cases de ce plan, cochées ou non.
4. Pour chaque écart : la ligne du plan, ce qui s'est passé, le message exact affiché (copie
   d'écran), et les lignes `event=…` du journal du noyau autour du moment de l'écart. Le
   journal ne contient aucun secret : il peut être copié tel quel.
5. Pour les prototypes matériels : la sortie complète des commandes de
   `docs/keystore-prototypes.md`.

## 9. Avant de publier

- [ ] Toutes les cases bloquantes cochées sur les quatre machines.
- [ ] `docs/livraison.md` § 6 « Avant de publier » vérifié.
- [ ] `SECURITY.md` : clé d'éditeur et empreinte GPG renseignées (plus de « À COMPLÉTER »).
