package cz.project.ewallet.model

import cz.project.ewallet.httpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType

class NetworkClient {
    suspend inline fun <reified T> get(url: String): T =
        httpClient.get(url).body()

    suspend inline fun <reified T, reified R> post(url: String, body: T): R =
        httpClient.post(url) {
            contentType(ContentType.Application.Json)
            setBody(body)
        }.body()
}
