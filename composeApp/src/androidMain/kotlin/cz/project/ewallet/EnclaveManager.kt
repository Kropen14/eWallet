package cz.project.ewallet

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate

class EnclaveManager {

        private lateinit var ks: KeyStore

        companion object { // NOTE: enables us to reference this constant via
                // EnclaveManager.BIOMETRIC_VAL_TIMEOUT
                private const val BIOMETRIC_VAL_TIMEOUT =
                        30 // INFO: Time window in which biometrics are valid

                const val ALIAS_QES_AUTH = "qes_auth_key"
                const val ALIAS_LOCAL_DEVICE = "local_device_key"
                const val ALIAS_ANDROID_KS = "AndroidKeyStore"
        }

        fun setup() { // INFO: Initiates Android KS connection
                ks = KeyStore.getInstance(ALIAS_ANDROID_KS)
                ks.load(null)
        }

        // INFO: Generates key for QES autorization on a remote QSCD
        fun generateQesAuthKey() {
                if (ks.containsAlias(ALIAS_QES_AUTH)) return

                generateKey(
                        alias = ALIAS_QES_AUTH,
                        purposes = KeyProperties.PURPOSE_SIGN,
                        requireAuth = true,
                        useStrongBox = false // TODO: Change to true when using a physical device
                )
        }

        // INFO: Generates a local key for offline presentation (ISO 18013-5)
        // 	Enables both signing and key agree for ECDH
        fun generateLocalDeviceKey() {
                if (ks.containsAlias(ALIAS_LOCAL_DEVICE)) return

                generateKey(
                        alias = ALIAS_LOCAL_DEVICE,
                        purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_AGREE_KEY,
                        requireAuth = true,
                        useStrongBox = false
                )
        }

        // INFO: Internal method for secure key generation
        private fun generateKey(
                alias: String,
                purposes: Int,
                requireAuth: Boolean,
                useStrongBox: Boolean
        ) {
                val keyGen =
                        KeyPairGenerator.getInstance(
                                KeyProperties
                                        .KEY_ALGORITHM_EC, // INFO: Generates via elyptical curves
                                ALIAS_ANDROID_KS
                        )

                val builder =
                        KeyGenParameterSpec.Builder(alias, purposes)
                                .setDigests(KeyProperties.DIGEST_SHA256)
                                .setUserAuthenticationRequired(requireAuth)
                                .setIsStrongBoxBacked(useStrongBox)
                                .setAttestationChallenge(
                                        "dummy_challenge_for_testing".toByteArray()
                                )
                // INFO: LoA High condition : Invalidate keys if new biometric entry is added

                builder.setUserAuthenticationParameters(
                        BIOMETRIC_VAL_TIMEOUT,
                        KeyProperties.AUTH_BIOMETRIC_STRONG
                )

                if (requireAuth) {
                        builder.setInvalidatedByBiometricEnrollment(true)
                }

                keyGen.initialize(builder.build())
                keyGen.generateKeyPair()
        }

        // INFO: Exports the certificate chain of a given key
        //	Is Used to prove to a authority that it was generated in a secure enviroment
        fun getAttestationChain(alias: String): Array<Certificate>? {
                return ks.getCertificateChain(alias)
        }

        // INFO: Generates initialized 'Signature' object which awaits unlocking from the user via
        // biometrics
        fun getSignatureObject(alias: String): Signature? {
                val privateKey = ks.getKey(alias, null) as? PrivateKey ?: return null
                return Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
        }

        // INFO: Returns pubkey part for registration with certification authority
        fun getPubKey(alias: String): java.security.PublicKey? {
                return ks.getCertificate(alias)?.publicKey
        }

        // INFO: Quick check if the key already exists
        fun hasKey(alias: String): Boolean {
                return try {
                        ks.containsAlias(alias)
                } catch (e: Exception) {
                        false
                }
        }

        fun deleteKey(alias: String) {
                try {
                        if (ks.containsAlias(alias)) {
                                ks.deleteEntry(alias)
                        }
                } catch (e: Exception) {
                        Log.e("Enclave", "Nepodařilo se smazat klíč: ${e.message}")
                }
        }
}
