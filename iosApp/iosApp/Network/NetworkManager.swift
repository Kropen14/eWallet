import AuthenticationServices
import Foundation
import OSLog
import Shared

class NetworkManager {
  private var authToken: String = ""
  private let kmpClient = NetworkClient()
  private var preferences = PListManager.load()

  public func ensureAuthenticated() async throws {
    if authToken.isEmpty {
      let requestBody = TokenRequest(
        login: preferences.bankIDAuthKey, password: preferences.bankIDAuthSecret)
      let token = try await kmpClient.requestAuthToken(request: requestBody)
      self.authToken = token
    }
  }

  func getBankIdLoginURL(ngrokUrl: String) async throws -> String {
    // ALWAYS ensure authentication happens before this call
    try await ensureAuthenticated()

    let response = try await kmpClient.getBankIdAuthRedirect(
      uriRet: ngrokUrl,
      token: self.authToken
    )
    return response.redirectUrl
  }
}
