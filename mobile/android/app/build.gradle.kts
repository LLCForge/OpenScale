import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Sürüm deponun kökündeki VERSION dosyasından gelir (1.2.3 → kod 10203);
// masaüstü sürümüyle aynı numara, aynı imzalı manifesto (ADR-0022, #183).
val openscaleVersion: String = rootDir.resolve("../../VERSION").readText().trim()
val versionParts = Regex("""^(\d+)\.(\d+)\.(\d+)$""").matchEntire(openscaleVersion)?.groupValues
    ?: error("VERSION 1.2.3 biçiminde olmalı: '$openscaleVersion'")
val openscaleVersionCode = versionParts[1].toInt() * 10000 + versionParts[2].toInt() * 100 + versionParts[3].toInt()

// İmza (#183): sahibin kendi anahtarı, depo dışında. Anahtar deposu yolu ve
// takma adı OPENSCALE_ANDROID_SIGNING dosyasından (varsayılan
// ~/.openscale-release/android-signing.properties: storeFile, keyAlias),
// parolalar yalnızca ortam değişkenlerinden (OPENSCALE_KEYSTORE_PASSWORD,
// OPENSCALE_KEY_PASSWORD) okunur; dosyaya parola yazılmaz. Dosya yoksa
// imzasız release APK üretilir (F-Droid kendi derler veya sahibin imzasını
// tekrarlanabilir derlemeyle karşılaştırır).
val signingFile = File(
    System.getenv("OPENSCALE_ANDROID_SIGNING")
        ?: "${System.getProperty("user.home")}/.openscale-release/android-signing.properties",
)
val signingProps: Properties? = signingFile.takeIf { it.isFile }?.let { f ->
    Properties().apply { f.inputStream().use { load(it) } }
}

android {
    namespace = "org.openscale.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.openscale.android"
        // 29 (Android 10): VpnService.isAlwaysOn/isLockdownEnabled (#175)
        // ve setMetered; daha eski sürüm desteklenmez.
        minSdk = 29
        targetSdk = 35
        versionCode = openscaleVersionCode
        versionName = openscaleVersion
    }

    signingConfigs {
        signingProps?.let { props ->
            create("owner") {
                storeFile = File(props.getProperty("storeFile") ?: error("storeFile eksik: $signingFile"))
                keyAlias = props.getProperty("keyAlias") ?: error("keyAlias eksik: $signingFile")
                storePassword = System.getenv("OPENSCALE_KEYSTORE_PASSWORD") ?: error("OPENSCALE_KEYSTORE_PASSWORD ayarlı değil")
                keyPassword = System.getenv("OPENSCALE_KEY_PASSWORD") ?: System.getenv("OPENSCALE_KEYSTORE_PASSWORD")
                // v1 (JAR) imzası minSdk 29'da gereksiz; v2+v3 yeter.
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // İmza: sahibin kendi anahtarı, Google Play'siz dağıtım (#183, P27).
            signingConfig = signingConfigs.findByName("owner")
            // Tekrarlanabilir derleme: APK'ya git bilgisi yazılmaz (AGP 8.3+).
            vcsInfo.include = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets["main"].java.srcDirs("src/main/kotlin")

    // F-Droid uyumu: APK'ya Google'a özel bağımlılık bilgisi yazılmaz.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // build-go.sh üretir; depoya işlenmez.
    implementation(files("libs/openscale.aar"))
}

// Tekrarlanabilir derleme (#183): AGP'nin temel profil (baseline.prof)
// üretimi derlemeden derlemeye farklı bayt verebilir; F-Droid'in önerdiği
// gibi kapatılır. Uygulama kütüphanesiz olduğundan profil kazancı yoktur.
tasks.configureEach {
    if (name.contains("ArtProfile")) {
        enabled = false
    }
}
