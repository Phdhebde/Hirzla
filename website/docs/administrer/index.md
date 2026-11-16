---
title: Installer le serveur hirzlad
description: Installer hirzlad, le serveur auto-hébergé de Hirzla, sous Linux - prérequis, initialisation du sceau par quorum, certificats TLS, port d'administration distinct, descellement au démarrage.
---

# Installer le serveur

`hirzlad` est le serveur du mode Serveur. Il relaie la synchronisation, tient l'annuaire des
clés publiques et le journal d'audit. Il est **aveugle** : il ne reçoit, ne stocke et ne
journalise aucun secret en clair ni aucune clé capable d'en déchiffrer un.

Cette page s'adresse à l'administrateur. La référence complète est le
[guide d'administration](https://github.com/Phdhebde/Hirzla/blob/main/docs/evaluation/guide-agd.md)
du dépôt.

## Ce qu'il vous faut

| | |
| --- | --- |
| Système | Linux x86-64 |
| Fichier | `hirzlad-<version>-linux-x86_64.tar.gz`, [téléchargé et vérifié](../installer/index.md) |
| Réseau | Une adresse IP joignable par les postes (port 7443 par défaut), et une interface d'administration séparée |
| Certificats | Un certificat TLS pour le serveur, émis par l'autorité de votre site ; un certificat pour le port d'administration ; une autorité pour les certificats clients des administrateurs |
| Dépositaires | Des personnes de confiance qui garderont les parts du sceau, par exemple 3 |
| Accès sortant | Aucun. `hirzlad` n'ouvre aucune connexion sortante |

## 1. Préparer le système

- Créez un compte de service dédié, sans shell.
- Répertoire de données en `0700`, clés TLS en `0600`.
- Ne versionnez jamais les fichiers `*.pem`, `*.key` ni les parts du sceau.

## 2. Initialiser le serveur

Une seule fois. Le **sceau** protège la clé racine du serveur. Il est partagé entre des
dépositaires : il en faut `--threshold` parmi `--shares` pour desceller le serveur.

```sh
hirzlad init --data /var/lib/hirzlad --threshold 2 --shares 3 --shares-out /root/parts
```

1. Remettez `share-1.bin` … `share-3.bin` aux dépositaires, puis effacez `/root/parts`.
2. Notez `server_key_fingerprint` : c'est l'**empreinte du serveur**, que les postes
   vérifient en le rejoignant.

!!! info "Ce que le sceau protège"
    Les parts descellent la clé racine **du serveur**. Elles n'ouvrent aucun secret
    d'utilisateur : le serveur n'en détient pas les clés.

## 3. Démarrer le serveur

```sh
hirzlad serve --data /var/lib/hirzlad --listen 192.0.2.10:7443 \
  --cert serveur.pem --key serveur.key \
  --admin-listen 127.0.0.1:7444 --admin-cert admin.pem --admin-key admin.key \
  --admin-client-ca ac-admin.pem
```

- **Adresses IP seulement** : un nom demanderait une résolution, donc une requête sortante.
- **Le port d'administration est distinct** et exige un certificat client signé par
  `--admin-client-ca`. Ne l'exposez que sur une interface d'administration.
- Filtrez et limitez le débit en amont par votre pare-feu.

## 4. Desceller

Le serveur démarre **scellé**. Les dépositaires remettent leurs parts par le port
d'administration, jusqu'au quorum :

```sh
ADM="--serveur 127.0.0.1:7444 --nom hirzlad.exemple --ac ac-site.pem \
     --certificat administrateur.pem --cle administrateur.key"

hirzlad admin etat $ADM                           # scellé ou descellé, parts reçues
hirzlad admin desceller $ADM --part share-1.bin   # chaque dépositaire, jusqu'au quorum
```

`--serveur` est une adresse IP. `--nom` est le nom inscrit dans le certificat TLS du serveur ;
il n'est jamais résolu. Effacez la part du poste d'administration après usage si elle n'y est
pas conservée sur un support amovible.

Le serveur est prêt : [créez les comptes et invitez les postes](comptes.md).

## Options de `hirzlad serve`

Chaque port est borné. Les valeurs par défaut conviennent à la plupart des sites.

| Option | Par défaut | Valeurs admises |
| --- | --- | --- |
| `--max-connections N` (appareils, total) | 1 024 | 1 à 65 536 |
| `--max-per-source N` (appareils, par adresse source) | 32 | 1 à 65 536, au plus le total |
| `--auth-timeout SECONDES` (délai pour s'authentifier) | 60 | 10 à 3 600 |
| `--admin-max-connections N` (administration, total) | 16 | 1 à 65 536 |
| `--admin-max-per-source N` (administration, par source) | 4 | 1 à 65 536, au plus le total |
| `--late-retention-days JOURS` (conservation des écritures d'un membre déjà retiré) | 30 | 8 à 365 |

- Un site dont beaucoup de postes sortent par une même adresse (NAT) relève
  `--max-per-source`.
- Choisissez `--late-retention-days` supérieur au plus long délai de quarantaine réglé dans
  les casiers du site (7 jours par défaut).
- Une valeur hors bornes ou une option inconnue arrête `hirzlad` avant qu'il lise les clés et
  ouvre les ports.
