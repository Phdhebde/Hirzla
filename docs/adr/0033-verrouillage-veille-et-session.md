# ADR 0033 — Verrouillage à la mise en veille et au verrouillage de session

- Statut : proposé
- Date : 2026-11-15

## Contexte

Le coffre se verrouille après `auto_lock_s` secondes d'inactivité et à la fermeture de
l'application de poste. Il restait ouvert quand le poste se mettait en veille ou que
l'utilisateur verrouillait sa session (`docs/api-locale.md` § 14, point 5) : un poste portable
refermé, ou laissé session verrouillée, gardait des clés de casier en mémoire du noyau jusqu'à
la fin du délai. La finition du mode Self demande ce verrouillage, sous Windows, macOS et Linux,
réglable et actif par défaut.

Contraintes :

- le noyau tourne hors de la session graphique quand il est démarré par la ligne de
  commande, et sans boucle d'événements ;
- `unsafe` n'est permis que dans `hirzla-keystore` (règle 6) ;
- aucune dépendance nouvelle qui contient de l'`unsafe` sans justification ;
- les deux réglages appartiennent au coffre (`format.md` § 5.6), comme les délais.

## Décision

Trois mécanismes, qui convergent vers une seule fonction du noyau,
`Core::system_event(kind)`, qui verrouille si le réglage correspondant du coffre le demande
(raisons `sleep` et `session_lock` dans le journal) :

1. **Saut d'horloge, partout.** À chaque tic, le noyau compare l'avance de l'horloge murale à
   celle de l'horloge monotone depuis le tic précédent. Un écart de plus de 30 s
   (`SLEEP_GAP`) signale une mise en veille : l'horloge monotone ne compte pas le temps de
   veille sous Linux et macOS. Ce verrouillage arrive **au réveil**, avant toute requête.
2. **Notifications natives, dans le noyau**, sous Windows et macOS, par
   `hirzla_keystore::platform::watch_system_events` :
   - Windows : `PowerRegisterSuspendResumeNotification` (rappel sur `PBT_APMSUSPEND`) et une
     fenêtre de messages seule (`HWND_MESSAGE`) inscrite par `WTSRegisterSessionNotification`
     (`WTS_SESSION_LOCK`), sur un fil dédié ;
   - macOS : `IORegisterForSystemPower` sur la boucle `CFRunLoop` d'un fil dédié
     (`kIOMessageSystemWillSleep`, acquitté par `IOAllowPowerChange`), et l'état
     `CGSSessionScreenIsLocked` de `CGSessionCopyCurrentDictionary` lu chaque seconde.
   Chaque bloc `unsafe` porte son commentaire `// SAFETY:`. Le noyau journalise au démarrage
   ce qu'il reçoit (`event=system_watch sleep=0|1 session_lock=0|1`).
3. **D-Bus, dans l'application de poste**, sous Linux, où le noyau n'a pas de session : elle
   écoute `PrepareForSleep(true)` de logind, le signal `Lock` et la propriété `LockedHint` de
   sa propre session logind, et `ActiveChanged(true)` de `org.freedesktop.ScreenSaver` ou
   `org.gnome.ScreenSaver`, puis envoie l'opération `SystemEvent` (60) de l'API locale v5.
   Elle utilise `gio` 0.18 (liaisons GLib), déjà présent dans le graphe par le moteur web GTK
   de Tauri, sur un fil et un contexte GLib à elle.

Les réglages `lock_on_sleep` et `lock_on_session_lock` valent `true` par défaut, se lisent et
s'écrivent par `GetSettings` et `SetSettings` (61, 62), et s'affichent dans les réglages de
l'application et de `hirzla settings`.

## Conséquences

- Sous Windows et macOS, le coffre se verrouille avant la veille et dès le verrouillage de la
  session, même sans application ouverte.
- Sous Linux, le verrouillage avant la veille et au verrouillage de session demande
  l'application de poste ouverte ; sans elle (ligne de commande seule), seul le saut d'horloge
  joue, au réveil. Un environnement sans logind ni économiseur d'écran D-Bus n'a que le saut
  d'horloge.
- Sous macOS, le verrouillage de l'écran est vu avec une seconde de retard au plus (lecture
  périodique) : il n'existe pas de notification publique sans Objective-C.
- Un changement manuel de l'horloge murale de plus de 30 s en avant verrouille le coffre :
  faux positif sans danger.
- Le saut d'horloge ne voit pas une veille sous Windows, où l'horloge monotone avance pendant
  la veille ; la notification native y supplée.
- Les fonctions FFI ajoutées élargissent la surface `unsafe` de `hirzla-keystore` ; les
  fonctionnalités `windows-sys` grandissent de `Win32_Graphics_Gdi`,
  `Win32_System_LibraryLoader`, `Win32_System_Power`, `Win32_System_RemoteDesktop` et
  `Win32_UI_WindowsAndMessaging`. Les fichiers Windows et macOS ont été vérifiés par
  `cargo clippy --target x86_64-pc-windows-msvc` et `--target aarch64-apple-darwin` ; ils
  restent à essayer sur des postes réels.

## Alternatives écartées

- **Tout dans l'application** : sous Windows et macOS, le noyau démarré par la ligne de
  commande resterait ouvert pendant la veille.
- **D-Bus dans le noyau sous Linux** : le noyau n'est pas forcément dans la session de
  l'utilisateur (bus de session absent), et il faudrait une dépendance D-Bus de plus dans le
  processus qui tient les clés.
- **Crate `objc2` pour la notification de verrouillage d'écran sous macOS**
  (`com.apple.screenIsLocked` par `NSDistributedNotificationCenter`) : une dépendance
  Objective-C de plus pour gagner une seconde ; la lecture de l'état de session, par
  `core-foundation` déjà présent dans `hirzla-keystore`, suffit.
- **Délai d'inactivité seul, plus court** : ne protège pas un portable refermé pendant le délai.
