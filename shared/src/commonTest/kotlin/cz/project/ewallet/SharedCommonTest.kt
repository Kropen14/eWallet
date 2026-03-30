package cz.project.ewallet

import io.ktor.http.HttpMethod
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.Serializable

@Serializable
data class TestResponse(val userId: Int, val id: Int, val title: String, val completed: Boolean)

class SharedCommonTest {

        @Test
        fun example() {
                assertEquals(3, 1 + 2)
        }

        @Test
        fun testSuccessfulGetRequest() = runTest {
                val response =
                        networkRequest {
                                        url("https://jsonplaceholder.typicode.com/todos/1")
                                        method(HttpMethod.Get)
                                        header("Accpet", "application/json")
                                }
                                .execute<TestTodo>()

                // 3. Assert that the JSON was successfully parsed into your Kotlin object
                assertNotNull(response)
                assertEquals(1, response.id)
        }
}
