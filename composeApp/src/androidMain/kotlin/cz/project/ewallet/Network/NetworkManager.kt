package cz.project.ewallet

import android.util.Log
import cz.project.ewallet.model.NetworkClient
import cz.project.ewallet.BuildConfig

class NetworkManager {
        private var authToken: String = ""
        private val kmpClient = NetworkClient()
        private val TAG = "NetworkManager"

        suspend fun ensureAuthenticated() {
                if (authToken.isEmpty()) {
                        Log.d(TAG, "Requesting new token via KMP NetworkClient...")

                        val requestBody =
                                TokenRequest(
                                        login = BuildConfig.BANKID_AUTH_KEY,
                                        password = BuildConfig.BANKID_AUTH_SECRET
                                )

                        this.authToken = kmpClient.requestAuthToken(requestBody)
                        Log.d(TAG, "Successfully authenticated.")
                }
        }

        suspend fun getBankIdLoginURL(ngrokUrl: String): String {
                Log.d(TAG, "Getting BankID redirect URL...")

                ensureAuthenticated()

                val response =
                        kmpClient.getBankIdAuthRedirect(uriRet = ngrokUrl, token = this.authToken)

                return response.redirectUrl
        }
}
