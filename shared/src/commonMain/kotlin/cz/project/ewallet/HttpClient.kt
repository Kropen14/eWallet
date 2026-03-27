package cz.project.ewallet

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json

// Add the config block parameter
expect fun createHttpClient(config: HttpClientConfig<*>.() -> Unit): HttpClient

val httpClient: HttpClient by lazy {
    createHttpClient {
        install(ContentNegotiation) {
            json(Json {
                ignoreUnknownKeys = true
                isLenient = true
            })
        }
    }
}
