import Foundation
import OSLog

struct UserData: Codable {
  let status: String
  let firstname: String
  let lastname: String
  let email: String
  let country: String
  let locality: String

  var commonName: String {
    return "\(firstname) \(lastname)"
  }
}

class JWTDecoder {
  static private var logger = Logger.category("JWTDecoder")

  static func decodePayload<T: Codable>(token: String, as type: T.Type) -> T? {
    let parts = token.components(separatedBy: ".")
    guard parts.count == 3 else {
      return nil
    }

    var payload64 = parts[1]

    //INFO: format Base64Url -> Base64
    payload64 = payload64.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "-", with: "/")

    //INFO: Pad the payload
    while payload64.count % 4 != 0 {
      payload64 += "="
    }

    guard let payloadData = Data(base64Encoded: payload64) else { return nil }

    do {
      return try JSONDecoder().decode(T.self, from: payloadData)
    } catch {
      logger.error("Error during JWT data parsing: \(error.localizedDescription)")
      return nil
    }
  }
}
