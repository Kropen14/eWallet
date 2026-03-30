package cz.project.ewallet.model

// Fíla Pašek je Pašák lowercase

import cz.project.ewallet.*
import io.ktor.client.call.body
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import kotlin.coroutines.cancellation.CancellationException

class NetworkClient {
        suspend inline fun <reified T> get(url: String): T = httpClient.get(url).body()

        suspend inline fun <reified T, reified R> post(url: String, body: T): R =
                httpClient
                        .post(url) {
                                contentType(ContentType.Application.Json)
                                setBody(body)
                        }
                        .body()

        @Throws(Exception::class, CancellationException::class)
        suspend fun getTestTodo(url: String): TestTodo {
                return get<TestTodo>(url)
        }

        @Throws(Exception::class, CancellationException::class)
        suspend fun loginUser(url: String, request: CreateUserRequest): LoginResponse {
                return post<CreateUserRequest, LoginResponse>(url, request)
        }

        @Throws(Exception::class)
        suspend fun requestAuthToken(request: TokenRequest): String {
                val response =
                        httpClient.submitForm(
                                url = "https://test.signosoft.com/api/restServerLogin",
                                formParameters =
                                        parameters {
                                                append("login", request.login)
                                                append("password", request.password)
                                        }
                        )

                if (!response.status.isSuccess()) {
                        throw Exception("Login failed with status: ${response.status.value}")
                }
                val loginResponse: LoginResponse = response.body()

                return loginResponse.token
        }

        @Throws(Exception::class)
        suspend fun getBankIdAuthRedirect(uriRet: String, token: String): BankIdRedirectResponse {
                val response =
                        httpClient.get("https://test.signosoft.com/api/REST/bankIdUser/auth") {
                                header("Authorization", "Bearer $token")
                                parameter("URI_RET", uriRet)
                        }

                if (response.status == HttpStatusCode.Unauthorized) {
                        throw Exception("BankID Auth rejected (401). Check if the token is valid.")
                }

                return response.body()
        }
}
