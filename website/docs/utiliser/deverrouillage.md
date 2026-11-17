---
title: Ouvrir avec Windows Hello, Touch ID ou une clé de sécurité
description: Ouvrir le coffre Hirzla d'un geste - Windows Hello, Touch ID ou une clé de sécurité FIDO2 - sans retaper le mot de passe maître, qui reste toujours valable.
---

# Ouvrir avec Windows Hello, Touch ID ou une clé de sécurité

Vous pouvez ouvrir le coffre d'un geste au lieu de taper le mot de passe maître :

| Méthode | Système | Ce qui est demandé |
| --- | --- | --- |
| Windows Hello | Windows 10 et 11 | Visage, empreinte ou code PIN Windows Hello |
| Touch ID | Mac Apple silicon ou à puce T2 | Empreinte |
| Clé de sécurité FIDO2 | Windows ; Linux et macOS selon la version installée | La clé branchée, son code PIN et un contact |

**Le mot de passe maître reste toujours valable.** Il est redemandé pour ajouter une méthode,
et il ouvre le coffre si la méthode échoue (appareil absent, empreintes modifiées, clé
réinitialisée). Gardez-le, et pensez au [kit de recouvrement](recouvrement.md).

!!! info "Clé de sécurité"
    La clé doit gérer l'extension `hmac-secret` (YubiKey 5, SoloKey 2, Token2… : la plupart
    des clés FIDO2 récentes). Une même clé ouvre le coffre sur tous les systèmes, et une copie
    du fichier sur un autre poste : c'est voulu. Vous pouvez enregistrer plusieurs clés, par
    exemple une de secours.

## Ajouter une méthode

1. Ouvrez le coffre, puis **Réglages › Déverrouillage**.
2. Cliquez sur **Ajouter Windows Hello…**, **Ajouter Touch ID…** ou **Ajouter Clé de sécurité
   FIDO2…**. Seules les méthodes disponibles sur ce poste sont proposées.
3. Confirmez votre mot de passe maître, puis suivez la demande du système.

Le coffre compte au plus huit méthodes, mot de passe compris.

## Ouvrir le coffre

L'écran de déverrouillage propose la méthode en premier : cliquez sur **Ouvrir avec Windows
Hello** (ou Touch ID, ou la clé de sécurité). Le mot de passe maître reste dessous.

Hirzla ne lance jamais la demande de lui-même : rien n'apparaît tant que vous n'avez pas
cliqué.

## Retirer une méthode

Dans **Réglages › Déverrouillage**, cliquez sur **Retirer** à côté de la dernière méthode de la
liste. Pour en retirer une autre, retirez d'abord celles qui la suivent. Une clé Windows Hello
retirée est aussi supprimée de Windows.

## Quand la méthode n'ouvre plus le coffre

Le message « La clé matérielle n'existe plus ou ne correspond plus » apparaît après une
réinitialisation de Windows Hello, l'ajout ou le retrait d'une empreinte Touch ID, ou la
réinitialisation de la clé de sécurité. Ouvrez le coffre avec le mot de passe maître, retirez
la méthode, puis ajoutez-la de nouveau.

## En ligne de commande

```sh
hirzla methods                     # méthodes du coffre et celles qu'on peut ajouter
hirzla methods add hello           # ou touchid, fido2 (coffre ouvert)
hirzla unlock --materiel           # la première méthode utilisable sur ce poste
hirzla unlock --materiel 2         # la méthode du rang 2
hirzla methods remove 2            # la dernière méthode seulement
```

## Ce qui est gardé, et ce qui ne l'est pas

La clé matérielle ne quitte jamais l'appareil. Le coffre n'en garde qu'une référence publique :
le nom de la clé Windows Hello, la clé de l'enclave sous une forme que seul ce Mac sait
utiliser, ou l'identifiant de la clé FIDO2. Il ne contient ni empreinte, ni code PIN, ni clé
publique. Le détail de la sécurité, y compris face à un futur ordinateur quantique, est dans
l'[ADR 0075](https://github.com/Phdhebde/Hirzla/blob/main/docs/adr/0075-deverrouillage-par-windows-hello-touch-id-et-fido2.md).
