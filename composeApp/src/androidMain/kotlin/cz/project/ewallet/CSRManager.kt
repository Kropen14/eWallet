package cz.project.ewallet

import android.util.Base64
import android.util.Log

class CSRManager(
        // INFO: Default constructor
        val tag: String,
        val commonName: String,
        val organization: String = "eWallet",
        val country: String = "CZ",
        val enclave: EnclaveManager
) {

        fun buildPEM(): String? {

                val derData = buildDER() ?: return null

                var header: String = "-----BEGIN CERTIFICATE REQUEST-----"
                var footer: String = "-----END CERTIFICATE REQUEST-----"

                val rawBase64 = Base64.encodeToString(derData, Base64.NO_WRAP)
                val base64 = rawBase64.chunked(64).joinToString("\n")

                val pemParts = listOf(header, base64, footer)
                val pemString = pemParts.joinToString("\n")

                return pemString + '\n'
        }

        private fun wrapSequence(data: ByteArray): ByteArray {
                return byteArrayOf(0x30) + encodeLength(data.size) + data
        }

        private fun encodeLength(length: Int): ByteArray {
                return if (length < 128) {
                        byteArrayOf(length.toByte())
                } else {
                        var temp = length
                        var bytes = ByteArray(0)
                        while (temp > 0) {
                                bytes = byteArrayOf((temp and 0xff).toByte()) + bytes
                                temp = temp shr 8
                        }
                        byteArrayOf((0x80 + bytes.size).toByte()) + bytes
                }
        }

        fun buildDER(): ByteArray? {

                // INFO: query pubkey
                val signatureObject = enclave.getSignatureObject(EnclaveManager.ALIAS_LOCAL_DEVICE)
                val pubKey = enclave.getPubKey(EnclaveManager.ALIAS_LOCAL_DEVICE)

                if (signatureObject == null || pubKey == null) {
                        Log.e("CSR", "Key or Signature object not found in enclave")
                        return null
                }

                var info = byteArrayOf(0x02, 0x01, 0x00) // Version 0
                info += encodeSubject()

                // INFO: kotlin already encodes in ASN.1
                info += pubKey.encoded

                // INFO: kotlin enforces explicit conversion to Byte
                info += byteArrayOf(0xA0.toByte(), 0x00) // Attributes empty

                val infoSequence = wrapSequence(info)

                // INFO: Sign the infoSequence
                val signatureBytes: ByteArray =
                        try {
                                signatureObject.update(infoSequence)
                                signatureObject.sign()
                        } catch (e: Exception) {
                                Log.e("CSR", "Signing failed: ${e.message}")
                                return null
                        }

                // INFO: Complete the final data
                var finalData = ByteArray(0)
                finalData += infoSequence

                // INFO: OICD for SHA-256
                finalData +=
                        wrapSequence(
                                byteArrayOf(
                                        0x06,
                                        0x08,
                                        0x2a,
                                        0x86.toByte(),
                                        0x48,
                                        0xce.toByte(),
                                        0x3d,
                                        0x04,
                                        0x03,
                                        0x02
                                )
                        )

                // INFO: Sign as bitstring
                var sigWithPadding = byteArrayOf(0x00)
                sigWithPadding += signatureBytes

                finalData += byteArrayOf(0x03) + encodeLength(sigWithPadding.size) + sigWithPadding

                return wrapSequence(finalData)
        }

        private fun encodeSubject(): ByteArray {
                fun encodeRDN(oid: ByteArray, value: String): ByteArray {
                        val valData = value.toByteArray(Charsets.UTF_8)
                        val stringType: Byte = 0x0c // UTF8String

                        val pairInner =
                                byteArrayOf(0x06, oid.size.toByte()) +
                                        oid +
                                        byteArrayOf(stringType) +
                                        encodeLength(valData.size) +
                                        valData
                        val pair = wrapSequence(pairInner)

                        return byteArrayOf(0x31) + encodeLength(pair.size) + pair
                }

                var subject = ByteArray(0)

                // INFO:  C (Country) - OID 2.5.4.6 -> hex: 55 04 06
                subject += encodeRDN(byteArrayOf(0x55, 0x04, 0x06), country)

                // INFO:  O (Organization) - OID 2.5.4.10 -> hex: 55 04 0A
                subject += encodeRDN(byteArrayOf(0x55, 0x04, 0x0a), organization)

                // INFO: CN (Common Name) - OID 2.5.4.3 -> hex: 55 04 03
                subject += encodeRDN(byteArrayOf(0x55, 0x04, 0x03), commonName)

                return wrapSequence(subject)
        }
}
