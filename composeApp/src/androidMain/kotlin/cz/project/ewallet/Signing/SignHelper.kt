package cz.project.ewallet

import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

fun authenticateAndSign(
        activity: FragmentActivity,
        enclave: EnclaveManager,
        pdfBytes: ByteArray,
        fileName: String = "document.pdf",
        onSignatureReady: (String) -> Unit
) {
        Log.d("FileHandler", "Starting JAdES preparation...")

        val jadesManager = JadesManager()
        val certChain = enclave.getAttestationChain(EnclaveManager.ALIAS_QES_AUTH)

        //  PREPARE THE DATA
        val jadesContext = jadesManager.prepareSigningInput(fileName, pdfBytes, certChain)
        if (jadesContext == null) {
                Log.e("FileHandler", "Failed to prepare JAdES context")
                return
        }

        val executor = ContextCompat.getMainExecutor(activity)

        val biometricPrompt =
                BiometricPrompt(
                        activity,
                        executor,
                        object : BiometricPrompt.AuthenticationCallback() {

                                override fun onAuthenticationSucceeded(
                                        result: BiometricPrompt.AuthenticationResult
                                ) {
                                        super.onAuthenticationSucceeded(result)
                                        Log.d(
                                                "FileHandler",
                                                "Fingerprint recognized! Keystore is now unlocked."
                                        )

                                        try {
                                                val signature =
                                                        enclave.getSignatureObject(
                                                                EnclaveManager.ALIAS_QES_AUTH
                                                        )
                                                                ?: throw Exception(
                                                                        "Failed to initialize Signature object"
                                                                )

                                                //  SIGN THE JWS STRING (NOT THE PDF)
                                                val derSignatureBytes =
                                                        enclave.signData(
                                                                signature,
                                                                jadesContext.signingInputData
                                                        )

                                                // ASSEMBLE THE FINAL JSON
                                                val finalJadesJson =
                                                        jadesManager.assembleFinalJades(
                                                                jadesContext,
                                                                derSignatureBytes
                                                        )

                                                if (finalJadesJson != null) {
                                                        Log.d(
                                                                "FileHandler",
                                                                "SUCCESS! JAdES Signature generated:"
                                                        )

                                                        onSignatureReady(finalJadesJson)
                                                }
                                        } catch (e: Exception) {
                                                Log.e(
                                                        "FileHandler",
                                                        "Error during signing: ${e.message}"
                                                )
                                        }
                                }

                                override fun onAuthenticationError(
                                        errorCode: Int,
                                        errString: CharSequence
                                ) {
                                        super.onAuthenticationError(errorCode, errString)
                                        Log.e(
                                                "FileHandler",
                                                "Biometric error [$errorCode]: $errString"
                                        )
                                }

                                override fun onAuthenticationFailed() {
                                        super.onAuthenticationFailed()
                                        Log.w("FileHandler", "Authentication failed")
                                }
                        }
                )

        val promptInfo =
                BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Sign Document")
                        .setSubtitle("Confirm your identity to create JAdES signature")
                        .setNegativeButtonText("Cancel")
                        .build()

        biometricPrompt.authenticate(promptInfo)
}
