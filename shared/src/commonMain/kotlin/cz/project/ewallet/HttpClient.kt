package cz.project.ewallet

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json

expect fun createHttpClient(config: HttpClientConfig<*>.() -> Unit): HttpClient

val httpClient: HttpClient = createHttpClient {
        install(ContentNegotiation) {
                json(
                        Json {
                                ignoreUnknownKeys = true
                                isLenient = true
                        }
                )
        }
}

suspend inline fun <reified ResponseType, reified RequestBody> sendNetworkRequest(
        urlString: String,
        httpMethod: HttpMethod,
        requestPayload: RequestBody? = null
): ResponseType {

        return httpClient
                .request(urlString) {
                        method = httpMethod

                        if (requestPayload != null) {
                                contentType(ContentType.Application.Json)
                                setBody(requestPayload)
                        }
                }
                .body()
}
