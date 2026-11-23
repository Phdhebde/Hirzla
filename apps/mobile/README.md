# Hirzla pour Android (ADR 0080)

Premier lot, en développement : créer et ouvrir le coffre, empreinte (StrongBox), liste,
affichage et copie, ajout d'un identifiant. Hors du Play Store ; APK de développement
seulement (une version de livraison du noyau refuse de démarrer tant que le contrôle du
certificat de l'APK n'est pas écrit).

- `core/` : `libhirzla_core_android.so`, le noyau, chargé par `CoreService` dans le processus
  `:core`.
- `src-tauri/` : l'interface (Tauri 2) ; `gen/android/` : le projet Gradle et la couche
  Kotlin (`MainActivity`, `CoreService`, `HirzlaPlugin`).
- `ui/` : les écrans, HTML et JavaScript sans framework.

## Construire et installer (Pixel branché, débogage USB autorisé)

```sh
export ANDROID_HOME=/chemin/vers/android-sdk
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.1.12297006" NDK_HOME="$ANDROID_HOME/ndk/27.1.12297006"
export JAVA_HOME=/chemin/vers/jdk-17
# Le noyau, toujours en release (Argon2id en debug est trop lent).
cargo ndk -t arm64-v8a -P 34 -o apps/mobile/src-tauri/gen/android/app/src/main/jniLibs \
  build --release -p hirzla-mobile-core
# L'interface et l'APK.
(cd apps/mobile/src-tauri && cargo tauri android build --debug --apk --target aarch64)
adb install -r apps/mobile/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

Journal du noyau (APK de développement) : `adb shell run-as app.hirzla.mobile cat files/core/core.log`.

## Android Studio

```sh
apps/mobile/scripts/studio.sh
```

Ouvre le projet Gradle avec l'environnement des constructions Rust (cargo, NDK, SDK). Un
« Run » sur le Pixel construit tout : l'interface (tâche `rustBuild…` de Tauri) et le noyau
(tâche `buildHirzlaCore`, toujours en release). Lancé depuis le Dock, Studio ne voit pas cargo
ni le NDK.
