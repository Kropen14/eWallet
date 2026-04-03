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
  //
  //NOTE: This function accepts RAW (unhashed) data and signs it using the message-level algorithm
  //      .ecdsaSignatureMessageX962SHA256 handles SHA-256 hashing internally inside the Secure Enclave
  //      Using the digest-level variant (.ecdsaSignatureDigestX962SHA256) with a pre-hashed input
  //      would cause double hashing: ECDSA(SHA256(SHA256(data))) — which is cryptographically wrong
  public func sign(data_to_sign: Data, tag: Data, context: LAContext) -> Data? {

    logger.log("Initiating signing process")

    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,  //INFO: Explicitly specify private key
      kSecReturnRef as String: true,
      kSecUseAuthenticationContext as String: context,  //INFO: Pass biometry context for hardware key access
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)

    guard status == errSecSuccess, let privateKey = item as! SecKey? else {
      logger.error("Private key not found. Keychain status: \(status)")
      return nil
    }

    var error: Unmanaged<CFError>?

    //INFO: Pass raw data directly — the message-level algorithm performs SHA-256 internally
    //      No manual pre-hashing here, that would result in signing SHA256(SHA256(data))
    guard
      let signature = SecKeyCreateSignature(
        privateKey,
        .ecdsaSignatureMessageX962SHA256,
        data_to_sign as CFData,
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
    originalDocument: Data, fileName: String, mimeType: String = "application/octet-stream",
    tag: Data, pubKeyData: Data, context: LAContext,
    userCert: SecCertificate
  ) -> Data? {

    logger.log("Initiating JAdES signing")

    //INFO: Compute the document hash — this is referenced in sigD, not embedded in the payload
    //      sigD is the JAdES standard mechanism for detached content signing
    let documentHash = SHA256.hash(data: originalDocument)
    let documentHashBase64 = Data(documentHash).base64UrlEncodedString()

    //INFO: sigT must be an RFC 3339 / ISO 8601 UTC timestamp
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let certificateChain: [String] = getCertificateChain(for: userCert)

    //INFO: Compute the SHA-256 digest of the DER-encoded signing certificate
    //      This is used in the sigCert header to cryptographically bind the cert to the signature
    let certData = SecCertificateCopyData(userCert) as Data
    let certHash = SHA256.hash(data: certData)
    let certHashBase64Url = Data(certHash).base64UrlEncodedString()

    //INFO: Extract issuer name and serial number from the certificate
    //      These are required alongside digVal to unambiguously identify the signing certificate
    //      per ETSI EN 119 182 — without them DSS reports signing-certificate as WARNING
    guard
      let issuerData = SecCertificateCopyNormalizedIssuerSequence(userCert) as Data?,
      let serialData = SecCertificateCopySerialNumberData(userCert, nil) as Data?
    else {
      logger.error("Failed to extract issuer or serial from certificate")
      return nil
    }
    let issuerBase64 = issuerData.base64UrlEncodedString()
    let serialBase64 = serialData.base64UrlEncodedString()

    //INFO: Transform the pubkey into the accepted JWK standard (uncompressed EC point, 0x04 prefix)
    guard pubKeyData.count == 65 && pubKeyData[0] == 0x04 else {
      logger.error("Unsupported pubkey format — expected 65-byte uncompressed EC point")
      return nil
    }
    let xBase64Url = pubKeyData.subdata(in: 1..<33).base64UrlEncodedString()
    let yBase64Url = pubKeyData.subdata(in: 33..<65).base64UrlEncodedString()

    // //INFO: sigCert — binds the signing certificate to the signature
    // //      digVal alone is insufficient; issuer + serial are required for unambiguous identification
    // let sigCert: [String: Any] = [
    //   "digAlg": "SHA-256",
    //   "digVal": certHashBase64Url,
    //   "issuer": issuerBase64,  //INFO: DER-encoded issuer name, base64url
    //   "serial": serialBase64,  //INFO: DER-encoded serial number, base64url
    // ]

    //INFO: sigD — required for detached JAdES signing (ETSI EN 119 182 §5.2.8)
    //      Describes the signed document by name and hash so the validator can locate and verify it
    //      Without sigD, DSS cannot perform reference data validation on a detached payload
    let sigD: [String: Any] = [
      "mId": "http://uri.etsi.org/19182/ObjectIdByURIHash",
      "pars": [fileName],
      "hashM": "S256",
      "hashV": [documentHashBase64],
      "ctys": [mimeType],
    ]

    //NOTE: jwk is intentionally included here as it helps DSS perform the math verification check
    //      It is not required by the standard and can be removed in a production hardened build
    let jwk: [String: String] = [
      "kty": "EC",
      "crv": "P-256",
      "x": xBase64Url,
      "y": yBase64Url,
    ]

    //INFO: crit lists all header parameters that MUST be understood by the verifier
    //      sigD is the critical one for detached content; sigT and sigCert are JAdES-defined
    let crit: [String] = ["sigD", "sigT"]

    //INFO: typ must be "jose+json" for JSON serialization per RFC 7515 §4.1.9
    //      Using "JAdES" here is non-standard and causes format warnings in DSS
    let header: [String: Any] = [
      "alg": "ES256",
      "typ": "jose+json",
      "sigT": timestamp,
      "x5c": certificateChain,
      "jwk": jwk,
      // "sigCert": sigCert,
      "x5t#S256": certHashBase64Url,
      "sigD": sigD,
      "crit": crit,
    ]

    //INFO: Payload still carries human-readable metadata but the canonical signed reference
    //      for the document is in sigD (protected header), not here
    let payload: [String: String] = [
      "document_name": fileName,
      "document_sha256": documentHashBase64,
    ]

    guard let headerData = try? JSONSerialization.data(withJSONObject: header),
      let payloadData = try? JSONSerialization.data(withJSONObject: payload)
    else {
      logger.error("Failed to serialize header or payload to JSON")
      return nil
    }

    let protectedB64 = headerData.base64UrlEncodedString()
    let payloadB64 = payloadData.base64UrlEncodedString()

    //INFO: JWS signing input is ASCII bytes of "BASE64URL(header).BASE64URL(payload)"
    //      This raw string is passed directly to sign() — no pre-hashing here
    //      sign() uses .ecdsaSignatureMessageX962SHA256 which handles SHA-256 internally
    let signingInputString = "\(protectedB64).\(payloadB64)"
    guard let signingInputData = signingInputString.data(using: .ascii),
      let derSignature = self.sign(data_to_sign: signingInputData, tag: tag, context: context)
    else {
      logger.error("Signing of JWS input failed")
      return nil
    }

    //INFO: DER → raw 64-byte (R || S) conversion required by JWS/JAdES
    guard let rawSignature = convertDERtoRawSignature(derSignature) else {
      logger.error("Conversion from DER to RAW64 failed")
      return nil
    }

    //INFO: Final JAdES JSON serialization per RFC 7515 §7.2
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

  // INFO: Načte testovací certifikát z přibaleného souboru cert.der
  public func getLocalTestCertificate() -> SecCertificate? {
    // 1. Najde soubor v projektu
    guard let certURL = Bundle.main.url(forResource: "cert", withExtension: "der"),
      let certData = try? Data(contentsOf: certURL)
    else {
      logger.error("Soubor cert.der nebyl nalezen v App Bundle.")
      return nil
    }

    // 2. Převede surová data na Apple SecCertificate objekt
    guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
      logger.error("Nepodařilo se vytvořit SecCertificate z dodaných dat.")
      return nil
    }

    return certificate
  }

}
