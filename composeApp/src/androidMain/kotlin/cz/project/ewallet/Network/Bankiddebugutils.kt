package cz.project.ewallet

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log

object BankIDDebugUtils {
        private const val TAG = "BankIDDebug"

        /** Test the complete authentication flow */
        suspend fun testCompleteFlow(networkManager: NetworkManager, context: Context) {
                Log.d(TAG, "========================================")
                Log.d(TAG, "Starting BankID Flow Test")
                Log.d(TAG, "========================================")

                // Step 1: Test authentication
                testAuthentication(networkManager)

                // Step 2: Test BankID URL generation
                testBankIDURL(networkManager)

                Log.d(TAG, "========================================")
                Log.d(TAG, "Test completed - check logs above")
                Log.d(TAG, "========================================")
        }

        /** Test backend authentication */
        suspend fun testAuthentication(networkManager: NetworkManager) {
                Log.d(TAG, "\n--- Testing Authentication ---")
                try {
                        networkManager.ensureAuthenticated()
                        Log.d(TAG, "✓ Authentication successful")
                } catch (e: Exception) {
                        Log.e(TAG, "✗ Authentication failed: ${e.message}")
                        Log.e(TAG, "Stack trace:", e)
                }
        }

        /** Test BankID URL generation */
        suspend fun testBankIDURL(networkManager: NetworkManager) {
                Log.d(TAG, "\n--- Testing BankID URL Generation ---")
                try {
                        val testCallback = "https://test-callback.ngrok.io"
                        val url = networkManager.getBankIdLoginURL(testCallback)
                        Log.d(TAG, "✓ BankID URL received:")
                        Log.d(TAG, "  URL: $url")
                        Log.d(TAG, "  Callback: $testCallback")
                } catch (e: Exception) {
                        Log.e(TAG, "✗ Failed to get BankID URL: ${e.message}")
                        Log.e(TAG, "Stack trace:", e)
                }
        }

        /** Test JWT token decoding */
        fun testJWTDecoding(token: String) {
                Log.d(TAG, "\n--- Testing JWT Decoding ---")
                Log.d(TAG, "Token (first 50 chars): ${token.take(50)}...")

                val userData = JWTDecoder.decodePayload(token)
                if (userData != null) {
                        Log.d(TAG, "✓ JWT decoded successfully:")
                        Log.d(TAG, "  Name: ${userData.commonName}")
                        Log.d(TAG, "  Email: ${userData.email}")
                        Log.d(TAG, "  Country: ${userData.country}")
                        Log.d(TAG, "  Locality: ${userData.locality}")
                        Log.d(TAG, "  Status: ${userData.status}")
                } else {
                        Log.e(TAG, "✗ JWT decoding failed")
                }
        }

        /** Test deep link handling */
        fun testDeepLink(context: Context, token: String = "test_token_123") {
                Log.d(TAG, "\n--- Testing Deep Link ---")
                val deepLinkUri = "ewallet://auth?token=$token"
                Log.d(TAG, "Deep link URI: $deepLinkUri")

                try {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(deepLinkUri))
                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        context.startActivity(intent)
                        Log.d(TAG, "✓ Deep link intent created and sent")
                } catch (e: Exception) {
                        Log.e(TAG, "✗ Deep link test failed: ${e.message}")
                }
        }

        /** Simulate BankID callback for testing without actual BankID */
        fun simulateBankIDCallback(token: String = createMockJWT(), onSuccess: (String) -> Unit) {
                Log.d(TAG, "\n--- Simulating BankID Callback ---")
                Log.d(TAG, "Mock token created (first 50 chars): ${token.take(50)}...")

                // Emit to the flow as if MainActivity received it
                bankIdTokenFlow.value = token
                onSuccess(token)

                Log.d(TAG, "✓ Token emitted to bankIdTokenFlow")
        }

        /** Create a mock JWT for testing (not cryptographically valid, but parseable) */
        fun createMockJWT(): String {
                // Header
                val header = """{"alg":"HS256","typ":"JWT"}"""
                val headerB64 =
                        android.util.Base64.encodeToString(
                                header.toByteArray(),
                                android.util.Base64.URL_SAFE or
                                        android.util.Base64.NO_PADDING or
                                        android.util.Base64.NO_WRAP
                        )

                // Payload with test user data
                val payload =
                        """{
            "status": "verified",
            "firstname": "Test",
            "lastname": "User",
            "email": "test@example.com",
            "country": "CZ",
            "locality": "Prague"
        }"""
                val payloadB64 =
                        android.util.Base64.encodeToString(
                                payload.toByteArray(),
                                android.util.Base64.URL_SAFE or
                                        android.util.Base64.NO_PADDING or
                                        android.util.Base64.NO_WRAP
                        )

                // Signature (fake)
                val signature = "fake_signature"
                val signatureB64 =
                        android.util.Base64.encodeToString(
                                signature.toByteArray(),
                                android.util.Base64.URL_SAFE or
                                        android.util.Base64.NO_PADDING or
                                        android.util.Base64.NO_WRAP
                        )

                return "$headerB64.$payloadB64.$signatureB64"
        }

        /** Test enclave key generation */
        fun testEnclaveKeys(enclave: EnclaveManager) {
                Log.d(TAG, "\n--- Testing Enclave Keys ---")

                try {
                        // Check if keys exist
                        val localExists = enclave.hasKey(EnclaveManager.ALIAS_LOCAL_DEVICE)
                        val qesExists = enclave.hasKey(EnclaveManager.ALIAS_QES_AUTH)

                        Log.d(TAG, "Local device key exists: $localExists")
                        Log.d(TAG, "QES auth key exists: $qesExists")

                        if (!localExists || !qesExists) {
                                Log.d(TAG, "Generating missing keys...")
                                enclave.generateLocalDeviceKey()
                                enclave.generateQesAuthKey()
                                Log.d(TAG, "✓ Keys generated successfully")
                        }

                        // Try to get public key
                        val pubKey = enclave.getPubKey(EnclaveManager.ALIAS_LOCAL_DEVICE)
                        if (pubKey != null) {
                                Log.d(TAG, "✓ Public key retrieved:")
                                Log.d(TAG, "  Algorithm: ${pubKey.algorithm}")
                                Log.d(TAG, "  Format: ${pubKey.format}")
                        } else {
                                Log.e(TAG, "✗ Failed to retrieve public key")
                        }
                } catch (e: Exception) {
                        Log.e(TAG, "✗ Enclave test failed: ${e.message}")
                        Log.e(TAG, "Stack trace:", e)
                }
        }

        /** Print current configuration */
        fun printConfiguration(context: Context) {
                Log.d(TAG, "\n--- Current Configuration ---")
                Log.d(TAG, "App package: ${context.packageName}")
                Log.d(TAG, "Expected deep link: ewallet://auth?token=...")

                // Check if deep link is registered
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse("ewallet://auth"))
                val activities = context.packageManager.queryIntentActivities(intent, 0)

                if (activities.isNotEmpty()) {
                        Log.d(TAG, "✓ Deep link handler registered")
                        activities.forEach { Log.d(TAG, "  Handler: ${it.activityInfo.name}") }
                } else {
                        Log.e(TAG, "✗ No deep link handler found!")
                        Log.e(TAG, "  Make sure AndroidManifest.xml has the intent filter")
                }
        }

        /** Comprehensive health check */
        suspend fun healthCheck(
                networkManager: NetworkManager,
                enclave: EnclaveManager,
                context: Context
        ) {
                Log.d(TAG, "\n========================================")
                Log.d(TAG, "BankID Implementation Health Check")
                Log.d(TAG, "========================================")

                printConfiguration(context)
                testEnclaveKeys(enclave)
                testAuthentication(networkManager)

                val mockToken = createMockJWT()
                testJWTDecoding(mockToken)

                Log.d(TAG, "\n========================================")
                Log.d(TAG, "Health Check Complete")
                Log.d(TAG, "========================================")
        }
}
