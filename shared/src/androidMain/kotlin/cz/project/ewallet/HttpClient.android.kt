package cz.project.ewallet

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.android.Android

actual fun createHttpClient(config: HttpClientConfig<*>.() -> Unit): HttpClient {
        return HttpClient(Android) {
                config(this)

                engine {
                        connectTimeout = 30_000
                        socketTimeout = 30_000
                }
        }
}
