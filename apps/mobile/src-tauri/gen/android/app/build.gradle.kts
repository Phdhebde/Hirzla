import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

android {
    compileSdk = 37
    namespace = "app.hirzla.mobile"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "app.hirzla.mobile"
        minSdk = 34
        targetSdk = 37
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {
                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            optimization {
               enable = true
            }
            proguardFiles(
                *fileTree(".") {
                  include("**/*.pro")
                  exclude("build/**")
                }.files.toTypedArray()
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    buildFeatures {
        buildConfig = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_1_8
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

apply(from = file("tauri.build.gradle.kts"))

// The core (ADR 0080 § 2): `libhirzla_core_android.so`, always in release (Argon2id in debug
// is far too slow), built by cargo-ndk into src/main/jniLibs before the native libraries are
// merged. The NDK is the one of local.properties (ndk.dir) or of ANDROID_NDK_HOME.
val buildCore = tasks.register<Exec>("buildHirzlaCore") {
    group = "rust"
    description = "Builds libhirzla_core_android.so (release, arm64-v8a)"
    val props = Properties().apply {
        val f = rootProject.file("local.properties")
        if (f.exists()) f.inputStream().use { load(it) }
    }
    val ndk = props.getProperty("ndk.dir") ?: System.getenv("ANDROID_NDK_HOME") ?: ""
    workingDir = rootProject.file("../../../../..")
    environment("ANDROID_NDK_HOME", ndk)
    val home = System.getProperty("user.home")
    environment("PATH", "$home/.cargo/bin:/opt/homebrew/bin:" + System.getenv("PATH"))
    // A GUI-launched Android Studio does not see the shell's PATH: rustup's cargo by default.
    val cargo = File("$home/.cargo/bin/cargo").takeIf { it.canExecute() }?.path ?: "cargo"
    commandLine(
        cargo, "ndk", "-t", "arm64-v8a", "-P", "34",
        "-o", "apps/mobile/src-tauri/gen/android/app/src/main/jniLibs",
        "build", "--release", "-p", "hirzla-mobile-core",
    )
}
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }
    .configureEach { dependsOn(buildCore) }
