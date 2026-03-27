package cz.project.ewallet

import io.ktor.http.HttpMethod
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.Serializable

@Serializable
data class TestTodo(val userId: Int, val id: Int, val title: String, val completed: Boolean)

class SharedCommonTest {

        @Test
        fun example() {
                assertEquals(3, 1 + 2)
        }

        @Test
        fun testSuccessfulGetRequest() = runTest {
                // 1. Make the actual network call to the public testing API
                // We use 'String' as a placeholder for RequestBody since we aren't sending one.
                val response =
                        sendNetworkRequest<TestTodo, String>(
                                urlString = "https://jsonplaceholder.typicode.com/todos/1",
                                httpMethod = HttpMethod.Get,
                                requestPayload = null
                        )

                // 2. Print the result to your console so you can see it working
                println("Network Response: $response")

                // 3. Assert that the JSON was successfully parsed into your Kotlin object
                assertNotNull(response)
                assertEquals(1, response.id)
        }
}
