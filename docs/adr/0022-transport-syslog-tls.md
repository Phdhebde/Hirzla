# ADR 0022 — Transport syslog sur TLS vers le SIEM

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

L'étape 12 demande l'export du journal d'audit en syslog sur TLS. `hirzla-audit` produit déjà
les messages RFC 5424 et leur cadrage RFC 5425 (`evenements.md` § 8.3) et les remet à un trait
`SyslogTransport`. Il manque la connexion TLS elle-même vers le collecteur du site.

Une bibliothèque TLS fait du réseau et contient ou appelle du code natif : `CLAUDE.md` demande
un ADR et une décision avant de l'ajouter. Elle n'a donc pas été ajoutée.

Contraintes :

- aucun appel réseau sortant non configuré : la connexion ne part que vers l'adresse que
  l'administrateur a saisie ;
- TLS 1.3 ; groupes hybrides post-quantiques quand le collecteur les accepte (`crypto.md`,
  Transport) ; beaucoup de collecteurs SIEM ne parlent que TLS 1.2 avec des courbes classiques ;
- authentification du collecteur par une AC du site épinglée, et du serveur Hirzla par un
  certificat client (RFC 5425 § 5.2 recommande l'authentification mutuelle) ;
- le contenu exporté ne contient aucun secret : TLS protège la confidentialité des
  métadonnées et l'intégrité du flux.

## Décision proposée

1. **`rustls`** avec le fournisseur cryptographique **`aws-lc-rs`**, déjà socle de
   `hirzla-crypto` (ADR 0009). Le transport vit dans `apps/server` (ou une petite crate
   `hirzla-siem`), pas dans `hirzla-audit`, qui reste sans réseau.
2. Profil : TLS 1.3 par défaut avec les groupes hybrides de `crypto.md`
   (`SecP384r1MLKEM1024`, puis `X25519MLKEM768`), groupes classiques seulement si le site
   l'autorise ; TLS 1.2
   autorisé seulement par un réglage explicite du site, pour les collecteurs anciens.
3. AC du collecteur fournie par le site, aucune AC système par défaut ; certificat client
   obligatoire ; adresse et port (6514, RFC 5425) saisis par l'administrateur.
4. File d'attente locale en cas de coupure ; le journal sur disque reste la référence et la
   reprise renvoie à partir du dernier rang acquitté par TCP. Les points de contrôle partent
   aussi vers le SIEM : ce sont eux qui révèlent une troncature (`evenements.md` § 6.1).
5. Demander un **numéro d'entreprise privé (PEN) à l'IANA** pour l'identifiant de données
   structurées ; en attendant, `hirzla@32473` (numéro d'exemple de la RFC 5612) est réglable.

## Conséquences

- Pas de seconde pile cryptographique : `rustls` sur `aws-lc-rs` réutilise AWS-LC.
- `rustls` est déjà prévu pour le transport poste ↔ serveur (`crypto.md`, Bibliothèques
  pressenties) : une seule bibliothèque TLS pour tout le produit.
- `rustls` n'a pas de code `unsafe` propre hors du fournisseur ; `aws-lc-rs` en a, déjà admis
  par l'ADR 0009.
- Le TLS 1.2 optionnel affaiblit la protection des métadonnées exportées contre un adversaire
  quantique futur ; c'est un choix du site, signalé dans l'interface.

## Alternatives écartées

- **OpenSSL (`openssl`, `native-tls`)** : seconde pile, dépendance système variable selon les
  postes, contraire au choix d'AWS-LC.
- **Laisser le transport à un relais externe** (rsyslog, stunnel) : aucun code TLS dans
  Hirzla, mais un composant de plus à configurer et à durcir, hors de la cible d'évaluation.
- **Syslog UDP ou TCP en clair** : métadonnées exposées et flux altérable ; refusé.
- **Ajouter `rustls` à `hirzla-audit`** : la crate du journal ferait du réseau ; elle doit
  rester vérifiable et utilisable hors ligne.
