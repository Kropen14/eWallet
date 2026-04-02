import Foundation
import OSLog

class PListManager {

  static var logger = Logger.category("PListManager")

  static private var pListUrl: URL? {
    return Bundle.main.url(forResource: "Secrets", withExtension: "plist")
  }

  static func load() -> AuthTokenAPIPreferences {
    let decoder = PropertyListDecoder()

    guard let url = pListUrl else {
      logger.error("File Secrets.plist not found in bundle")
      return AuthTokenAPIPreferences(bankIDAuthKey: "", bankIDAuthSecret: "")
    }

    do {
      let data = try Data(contentsOf: url)
      let preferences = try decoder.decode(AuthTokenAPIPreferences.self, from: data)
      return preferences
    } catch {
      logger.error("Error during pList decoding: \(error.localizedDescription)")
      return AuthTokenAPIPreferences(bankIDAuthKey: "", bankIDAuthSecret: "")
    }
  }
}

struct APIPreferences: Codable {
  var Key: String
  var Secret: String
}

struct AuthTokenAPIPreferences: Codable {
  var bankIDAuthKey: String
  var bankIDAuthSecret: String
}
