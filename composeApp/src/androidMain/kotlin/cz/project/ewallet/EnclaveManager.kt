import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate

class EnclaveManager {

        private lateinit var ks: KeyStore

        fun setup() {
                ks = KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
        }

        fun generateDeviceKey(alias: String) {

                // INFO: Avoid recreating a key
                if (ks.containsAlias(alias)) {
                        return
                }

                var key_gen: KeyPairGenerator =
                        KeyPairGenerator.getInstance(
                                KeyProperties.KEY_ALGORITHM_EC,
                                "AndroidKeyStore"
                        )
                var key_spec =
                        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN).apply {
                                setDigests(KeyProperties.DIGEST_SHA256)
                                setUserAuthenticationRequired(true)
                                setIsStrongBoxBacked(
                                        false
                                ) // NOTE: set to true if were not running an emulator
                        }

                var spec = key_spec.build()
                key_gen.initialize(spec)
                key_gen.generateKeyPair()
        }

        fun getAttestationChain(alias: String): Array<Certificate>? {
                return ks.getCertificateChain(alias)
        }

        fun getSignatureObject(alias: String): Signature? {
                val private_key = ks.getKey(alias, null) as? PrivateKey ?: return null

                return Signature.getInstance("SHA256withECDSA").apply { initSign(private_key) }
        }

        fun getPubKey(alias: String): java.security.PublicKey? {
                val cert = ks.getCertificate(alias)
                return cert?.publicKey
        }
}
