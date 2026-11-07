// OpenScale Android uygulaması (#173, ADR-0101). Go çekirdeği gomobile ile
// app/libs/openscale.aar olarak üretilir (build-go.sh); AndroidX dahil
// üçüncü taraf kütüphane kullanılmaz.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "OpenScale"
include(":app")
