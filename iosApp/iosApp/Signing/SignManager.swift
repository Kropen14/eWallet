import CryptoKit
import Foundation
import LocalAuthentication
import OSLog

// INFO: JWS standard helper
extension Data {
  func base64UrlEncodedString() -> String {
    return self.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}

class SignManager {

  private let logger = Logger.category("Signing")

  //NOTE: One can notice that our biometry class is not called in this function
  //      This is by design, the key itself can only be used when biometrically authenticated
  //      this property is specified during key generation
  public func sign(data_to_sign: Data, tag: Data, context: LAContext) -> Data? {

    logger.log("Initiating signing process")

    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,  //INFO: Explicitly specify private key
      kSecReturnRef as String: true,
      kSecUseAuthenticationContext as String: context,  //INFO: Pass biometry text
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)

    guard status == errSecSuccess, let privateKey = item as! SecKey? else {
      logger.error("Private key not found. Keychain status: \(status)")
      return nil
    }

    var error: Unmanaged<CFError>?

    let hash = SHA256.hash(data: data_to_sign)
    let hashed_data = Data(hash)

    guard
      let signature = SecKeyCreateSignature(
        privateKey,
        .ecdsaSignatureDigestX962SHA256,
        hashed_data as CFData,
        &error
      )
    else {
      let err = error?.takeRetainedValue()
      logger.error(
        "Signature inside secure enclave failed, error: \(err?.localizedDescription ?? "Unknown error", privacy: .public)"
      )
      return nil
    }

    logger.info("Data successfully signed with hardware key")
    return signature as Data

  }

  public func signAsJAdES(
    originalDocument: Data, fileName: String, tag: Data, pubKeyData: Data, context: LAContext,
    userCert: SecCertificate
  ) -> Data? {

    logger.log("Initiating signing")

    let documentHash = SHA256.hash(data: originalDocument)
    let documentHashBase64 = Data(documentHash).base64EncodedString()
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let certificateChain: [String] = getCertificateChain(for: userCert)

    //INFO: Transform the pubkey into the accepted standard
    guard pubKeyData.count == 65 && pubKeyData[0] == 0x04 else {
      logger.error("Unsupported pubkey format")
      return nil
    }
    let xBase64Url = pubKeyData.subdata(in: 1..<33).base64UrlEncodedString()
    let yBase64Url = pubKeyData.subdata(in: 33..<65).base64UrlEncodedString()

    let jwk: [String: String] = [
      "kty": "EC",
      "crv": "P-256",
      "x": xBase64Url,
      "y": yBase64Url,
    ]

    //INFO: header with timestamp and pubkey
    let header: [String: Any] = [
      "alg": "ES256",
      "typ": "JAdES",
      "sigT": timestamp,
      "x5c": certificateChain,
      "jwk": jwk,  //NOTE: tool for math check (DSS)
    ]

    let payload: [String: String] = [
      "document_name": fileName,
      "document_sha256": documentHashBase64,
    ]

    guard let headerData = try? JSONSerialization.data(withJSONObject: header),
      let payloadData = try? JSONSerialization.data(withJSONObject: payload)
    else {
      return nil
    }

    let protectedB64 = headerData.base64UrlEncodedString()
    let payloadB64 = payloadData.base64UrlEncodedString()

    //INFO: Merge and sign
    let signingInputString = "\(protectedB64).\(payloadB64)"
    guard let signingInputData = signingInputString.data(using: .ascii),
      let derSignature = self.sign(data_to_sign: signingInputData, tag: tag, context: context)
    else {
      return nil
    }

    guard let rawSignature = convertDERtoRawSignature(derSignature) else {
      logger.error("Conversion from DER to RAW64 failed")
      return nil
    }

    // INFO: Complete the final JSON
    let jadesJSON: [String: Any] = [
      "payload": payloadB64,
      "protected": protectedB64,
      "signature": rawSignature.base64UrlEncodedString(),
    ]

    return try? JSONSerialization.data(withJSONObject: jadesJSON, options: [.prettyPrinted])
  }

  // INFO: Převádí ASN.1 DER podpis z Apple Secure Enclave na 64-byte Raw formát vyžadovaný pro JWS/JAdES
  private func convertDERtoRawSignature(_ der: Data) -> Data? {
    var raw = Data()
    var index = 0

    // Očekáváme Sequence (0x30)
    guard der[index] == 0x30 else { return nil }
    index += 1
    let _ = Int(der[index])  // Délka sekvence
    index += 1

    // Extrakce R (0x02)
    guard der[index] == 0x02 else { return nil }
    index += 1
    let rLen = Int(der[index])
    index += 1
    var rData = der.subdata(in: index..<(index + rLen))
    if rData.count == 33 && rData[0] == 0x00 { rData = rData.dropFirst() }  // Odstranění paddingu
    while rData.count < 32 { rData.insert(0x00, at: 0) }  // Doplnění na 32 bajtů
    raw.append(rData)
    index += rLen

    // Extrakce S (0x02)
    guard der[index] == 0x02 else { return nil }
    index += 1
    let sLen = Int(der[index])
    index += 1
    var sData = der.subdata(in: index..<(index + sLen))
    if sData.count == 33 && sData[0] == 0x00 { sData = sData.dropFirst() }  // Odstranění paddingu
    while sData.count < 32 { sData.insert(0x00, at: 0) }  // Doplnění na 32 bajtů
    raw.append(sData)

    guard raw.count == 64 else { return nil }
    return raw
  }

  private func getCert(certificate: SecCertificate) -> String {
    let data = SecCertificateCopyData(certificate) as Data
    return data.base64EncodedString()
  }

  private func getCertificateChain(for certificate: SecCertificate) -> [String] {
    var certs: [SecCertificate] = [certificate]
    var policy = SecPolicyCreateBasicX509()
    var trust: SecTrust?

    SecTrustCreateWithCertificates(certificate, policy, &trust)

    if let trust = trust, let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
      certs = chain
    }

    return certs.map { getCert(certificate: $0) }
  }

  public func findCertificate(tag: Data) -> SecCertificate? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassCertificate,
      kSecAttrLabel as String: tag,
      kSecReturnRef as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)

    if status == errSecSuccess {
      return (item as! SecCertificate)
    }
    return nil
  }

}
