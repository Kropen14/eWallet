package cz.project.ewallet

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.*
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class TestTodo(val userId: Int, val id: Int, val title: String, val completed: Boolean)

@Serializable data class User(val id: Int, val name: String, val email: String)

@Serializable
data class LoginResponse(val token: String, val userId: Int? = null, val expiresIn: Long? = null)

@Serializable data class CreateUserRequest(val name: String, val email: String)

@Serializable data class TokenRequest(val login: String, val password: String)

@Serializable data class BankIdRedirectResponse(val redirectUrl: String)

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

class NetworkRequestBuilder {
        var url: String = "" // Public by default
        var method: HttpMethod = HttpMethod.Get
        var requestBody: Any? = null
        val headers = mutableMapOf<String, String>()
        val queryParams = mutableMapOf<String, String>()
        var customContentType: ContentType? = null
        var additionalConfig: (HttpRequestBuilder.() -> Unit)? = null

        fun url(url: String) = apply { this.url = url }

        fun method(method: HttpMethod) = apply { this.method = method }

        fun <T> body(body: T) = apply { this.requestBody = body }

        fun header(key: String, value: String) = apply { headers[key] = value }

        fun headers(vararg pairs: Pair<String, String>) = apply { headers.putAll(pairs) }

        fun headers(map: Map<String, String>) = apply { headers.putAll(map) }

        fun bearerAuth(token: String) = apply { headers["Authorization"] = "Bearer $token" }

        fun queryParam(key: String, value: String) = apply { queryParams[key] = value }

        fun queryParams(vararg pairs: Pair<String, String>) = apply { queryParams.putAll(pairs) }

        fun queryParams(map: Map<String, String>) = apply { queryParams.putAll(map) }

        fun contentType(contentType: ContentType) = apply { this.customContentType = contentType }

        fun configure(block: HttpRequestBuilder.() -> Unit) = apply {
                this.additionalConfig = block
        }

        suspend inline fun <reified ResponseType> execute(): ResponseType {
                return httpClient
                        .request(url) {
                                this.method = this@NetworkRequestBuilder.method

                                // Set headers
                                headers {
                                        this@NetworkRequestBuilder.headers.forEach { (key, value) ->
                                                append(key, value)
                                        }
                                }

                                // Set query parameters
                                queryParams.forEach { (key, value) -> parameter(key, value) }

                                // Set body if present
                                if (requestBody != null) {
                                        contentType(
                                                customContentType ?: ContentType.Application.Json
                                        )
                                        setBody(requestBody!!)
                                }

                                // Apply additional configuration
                                additionalConfig?.invoke(this)
                        }
                        .body()
        }
}

// Helper function to create the builder
fun networkRequest(block: NetworkRequestBuilder.() -> Unit = {}): NetworkRequestBuilder {
        return NetworkRequestBuilder().apply(block)
}
