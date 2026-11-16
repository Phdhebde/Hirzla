<!--
Modèle des notes de version (ADR 0064). Le flux « Livraison » remplace {{ETAT}} (étape du
flux), {{VERSION}}, {{NOTES}} (section de CHANGELOG.md pour cette version) et {{MARQUE}}
(numéro de l'exécution de l'étape 1, relu par l'étape 2 : ne pas le retirer du brouillon).
Ce commentaire n'est pas recopié.
-->
{{ETAT}}

## Hirzla {{VERSION}}

Coffre-fort de mots de passe post-quantique pour Windows, macOS et Linux, seul sur un poste
(mode Self) ou relié à un serveur `hirzlad` qui ne peut rien lire (mode Serveur).

{{NOTES}}

## Téléchargements

| Système | Fichier |
| --- | --- |
| Windows 10 et 11 (x64) | `Hirzla_{{VERSION}}_x64_fr-FR.msi` |
| macOS 11 et suivants (Apple Silicon) | `Hirzla_{{VERSION}}_aarch64.pkg` |
| Debian, Ubuntu (x86-64) | `Hirzla_{{VERSION}}_amd64.deb` |
| Fedora, RHEL, openSUSE (x86-64) | `Hirzla-{{VERSION}}-1.x86_64.rpm` |
| Autres Linux (x86-64) | `Hirzla_{{VERSION}}_amd64.AppImage`, s'il est présent (voir « Limites ») |
| Ligne de commande seule, Linux | `hirzla-cli-{{VERSION}}-linux-x86_64.tar.gz` |
| Serveur `hirzlad`, Linux | `hirzlad-{{VERSION}}-linux-x86_64.tar.gz` |
| Extension Firefox et Chromium | `hirzla-extension-{{VERSION}}.zip` |

Chaque installeur dépose côte à côte le noyau `hirzla-core`, l'application, la ligne de
commande `hirzla` et l'hôte natif de l'extension, avec le manifeste des clients
`hirzla-clients.manifest`, signé hors ligne par la clé d'éditeur hybride (ECDSA P-384 +
ML-DSA-87). Le noyau refuse de démarrer sans lui. Sous macOS, le paquet `.pkg` installe
`Hirzla.app` dans `/Applications` et le manifeste, hors de l'application, dans
`/Library/Application Support/Hirzla/` (propriété de root). Les manifestes de chaque plateforme
(`hirzla-clients-<plateforme>.manifest`) et les nomenclatures logicielles CycloneDX
(`*.cdx.json`) sont joints à cette page.

## Vérifier un téléchargement

1. Empreintes : `sha256sum -c SHA256SUMS --ignore-missing`.
2. Signature des empreintes, avec la clé GPG de livraison publiée dans `SECURITY.md` :
   `gpg --verify SHA256SUMS.asc SHA256SUMS`.
3. Provenance de compilation (Sigstore) :
   `gh attestation verify FICHIER --repo Phdhebde/Hirzla`.
4. Manifeste des clients, avec la clé publique d'éditeur publiée dans `SECURITY.md` :
   `hirzla-signer verifier --publique editeur.pub hirzla-clients-linux-x86_64.manifest`.

## Avertissements à l'installation

Les installeurs ne portent pas de signature de système (ADR 0063) : Windows affiche
« Windows a protégé votre ordinateur » (*Informations complémentaires* › *Exécuter quand
même*) ; macOS refuse d'ouvrir un paquet d'un développeur non identifié (clic droit sur le
`.pkg` › *Ouvrir*, ou `sudo installer -pkg Hirzla_{{VERSION}}_aarch64.pkg -target /`).
L'installation sous macOS demande les droits d'administrateur. Le produit vérifie quand même ses propres exécutables par la clé d'éditeur. Aucun
installeur ne télécharge quoi que ce soit ; l'application fonctionne en réseau isolé.

## Limites

- **macOS** : paquet d'installation `.pkg` seulement, pas d'image disque (ADR 0065) ; une
  copie de `Hirzla.app` glissée ailleurs à la main ne trouve son manifeste que si le `.pkg`
  de la même version est installé.
- **AppImage** : publiée seulement si ses exécutables sont identiques, octet pour octet, à
  ceux du manifeste signé (le flux le vérifie et l'écarte sinon).

{{MARQUE}}
