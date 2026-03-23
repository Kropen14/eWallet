package cz.project.ewallet

import android.util.Base64
import android.util.Log
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import org.json.JSONArray
import org.json.JSONObject

class JadesManager {

        // Helper for Base64Url encoding (matching Swift's base64UrlEncodedString)
        private fun ByteArray.encodeToBase64Url(): String {
                return Base64.encodeToString(
                        this,
                        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                )
        }

        private fun ByteArray.encodeToBase64Standard(): String {
                return Base64.encodeToString(this, Base64.DEFAULT or Base64.NO_WRAP)
        }

        // Prepares the "Header.Payload" string that needs to be signed
        fun prepareSigningInput(
                fileName: String,
                pdfBytes: ByteArray,
                certChain: Array<java.security.cert.Certificate>?
        ): SigningContext? {
                Log.d("JadesManager", "Preparing JAdES Payload and Header")

                if (certChain == null || certChain.isEmpty()) {
                        Log.e("JadesManager", "Certificate chain is empty")
                        return null
                }

                try {
                        // Hash the document
                        val digest = MessageDigest.getInstance("SHA-256")
                        val documentHash = digest.digest(pdfBytes)
                        val documentHashBase64 = documentHash.encodeToBase64Standard()

                        val sdf =
                                java.text.SimpleDateFormat(
                                        "yyyy-MM-dd'T'HH:mm:ss'Z'",
                                        java.util.Locale.US
                                )
                        sdf.timeZone = java.util.TimeZone.getTimeZone("UTC")
                        val timestamp = sdf.format(java.util.Date())

                        // Get user certificate
                        val userCert = certChain[0] as X509Certificate
                        val ecPubKey = userCert.publicKey as ECPublicKey
                        val xBase64Url =
                                padTo32Bytes(ecPubKey.w.affineX.toByteArray()).encodeToBase64Url()
                        val yBase64Url =
                                padTo32Bytes(ecPubKey.w.affineY.toByteArray()).encodeToBase64Url()

                        // Calculate Certificate Hash (x5t#S256) for ETSI compliance
                        val certHash = digest.digest(userCert.encoded)
                        val x5tS256 = certHash.encodeToBase64Url()

                        // Map certificates to Base64 strings
                        val x5cArray = JSONArray()
                        certChain.forEach { cert ->
                                x5cArray.put(cert.encoded.encodeToBase64Standard())
                        }

                        // Construct JWK
                        val jwk =
                                JSONObject().apply {
                                        put("kty", "EC")
                                        put("crv", "P-256")
                                        put("x", xBase64Url)
                                        put("y", yBase64Url)
                                }

                        // Construct Header (Updated for better ETSI compliance)
                        val header =
                                JSONObject().apply {
                                        put("alg", "ES256")
                                        put("typ", "JAdES")
                                        put("x5c", x5cArray)
                                        // The certificate thumbprint is mandatory for ETSI
                                        put("x5t#S256", x5tS256)
                                        // Keep sigT, but ensure it's formatted as a string
                                        put("sigT", timestamp)
                                        put("jwk", jwk)
                                }

                        // Construct Payload
                        val payload =
                                JSONObject().apply {
                                        put("document_name", fileName)
                                        put("document_sha256", documentHashBase64)
                                }

                        val protectedB64 =
                                header.toString().toByteArray(Charsets.UTF_8).encodeToBase64Url()
                        val payloadB64 =
                                payload.toString().toByteArray(Charsets.UTF_8).encodeToBase64Url()

                        val signingInputString = "$protectedB64.$payloadB64"

                        return SigningContext(
                                signingInputData =
                                        signingInputString.toByteArray(Charsets.US_ASCII),
                                protectedB64 = protectedB64,
                                payloadB64 = payloadB64
                        )
                } catch (e: Exception) {
                        Log.e("JadesManager", "Failed to prepare signing input: ${e.message}")
                        return null
                }
        }

        //  Takes the Android DER signature and constructs the final JSON
        fun assembleFinalJades(context: SigningContext, derSignature: ByteArray): String? {
                Log.d("JadesManager", "Assembling final JAdES JSON")

                val rawSignature = convertDERtoRawSignature(derSignature)
                if (rawSignature == null) {
                        Log.e("JadesManager", "Failed to convert DER to RAW signature")
                        return null
                }

                try {
                        val jadesJSON =
                                JSONObject().apply {
                                        put("payload", context.payloadB64)
                                        put("protected", context.protectedB64)
                                        put("signature", rawSignature.encodeToBase64Url())
                                }
                        return jadesJSON.toString(4) + '\n' // Pretty print with 4 spaces indent
                } catch (e: Exception) {
                        Log.e("JadesManager", "Failed to assemble JSON: ${e.message}")
                        return null
                }
        }

        // Exact replica of iOS convertDERtoRawSignature
        // Android Keystore ECDSA also outputs ASN.1 DER sequence
        private fun convertDERtoRawSignature(der: ByteArray): ByteArray? {
                try {
                        var index = 0
                        if (der[index++] != 0x30.toByte()) return null
                        index++ // Skip sequence length

                        // Extract R
                        if (der[index++] != 0x02.toByte()) return null
                        val rLen = der[index++].toInt()
                        var rData = der.copyOfRange(index, index + rLen)
                        index += rLen

                        // Extract S
                        if (der[index++] != 0x02.toByte()) return null
                        val sLen = der[index++].toInt()
                        var sData = der.copyOfRange(index, index + sLen)

                        // Strip leading zero padding if it exists
                        if (rData.size == 33 && rData[0] == 0x00.toByte())
                                rData = rData.copyOfRange(1, 33)
                        if (sData.size == 33 && sData[0] == 0x00.toByte())
                                sData = sData.copyOfRange(1, 33)

                        // Pad to exactly 32 bytes
                        rData = padTo32Bytes(rData)
                        sData = padTo32Bytes(sData)

                        // Combine R and S (64 bytes total)
                        val raw = ByteArray(64)
                        System.arraycopy(rData, 0, raw, 0, 32)
                        System.arraycopy(sData, 0, raw, 32, 32)

                        return raw
                } catch (e: Exception) {
                        Log.e("JadesManager", "DER parsing error: ${e.message}")
                        return null
                }
        }

        private fun padTo32Bytes(data: ByteArray): ByteArray {
                if (data.size == 32) return data
                // If smaller than 32, pad with leading zeros (or trim if > 32)
                val result = ByteArray(32)
                val startPos = if (data.size < 32) 32 - data.size else 0
                val copyLen = if (data.size < 32) data.size else 32
                System.arraycopy(
                        data,
                        if (data.size > 32) data.size - 32 else 0,
                        result,
                        startPos,
                        copyLen
                )
                return result
        }

        // Data class to hold context between biometric prompt execution
        data class SigningContext(
                val signingInputData: ByteArray,
                val protectedB64: String,
                val payloadB64: String
        )
}
