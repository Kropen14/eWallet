package cz.project.ewallet

import android.util.Base64
import android.util.Log
import org.json.JSONObject

data class UserData(
        val status: String,
        val firstname: String,
        val lastname: String,
        val email: String,
        val country: String,
        val locality: String
) {
        val commonName: String
                get() = "$firstname $lastname"
}

object JWTDecoder {
        fun decodePayload(token: String): UserData? {
                try {
                        val parts = token.split(".")
                        if (parts.size != 3) return null

                        val payloadBase64 = parts[1]
                        val decodedBytes = Base64.decode(payloadBase64, Base64.URL_SAFE)
                        val decodedString = String(decodedBytes, Charsets.UTF_8)

                        val json = JSONObject(decodedString)

                        return UserData(
                                status = json.optString("status", "unknown"),
                                firstname = json.optString("firstname", "Neznámé"),
                                lastname = json.optString("lastname", "Jméno"),
                                email = json.optString("email", "no@mail.com"),
                                country = json.optString("country", "CZ"),
                                locality = json.optString("locality", "Neznámá lokalita")
                        )
                } catch (e: Exception) {
                        Log.e("JWTDecoder", "Error during token parsing: ${e.message}")
                        return null
                }
        }
}
