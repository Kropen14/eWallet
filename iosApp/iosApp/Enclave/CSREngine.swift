import Foundation
import OSLog
import Security

class CSREngine {
  private let logger = Logger.category("CSR")
  private var commonName: String
  private var organization: String
  private var organizational_unit: String
  private var locality: String
  private var state: String
  private var country: String
  private var email: String
  private var tag: Data

  init(
    tag: Data, commonName: String, organization: String, organizational_unit: String,
    locality: String, state: String, country: String, email: String
  ) {
    self.tag = tag
    self.commonName = commonName
    self.organization = organization
    self.organizational_unit = organizational_unit
    self.locality = locality
    self.state = state
    self.country = country
    self.email = email
  }

  public func buildPEM() -> String? {
    guard let derData = buildDER() else { return nil }

    //INFO: Encode the data in base64
    let base64 = derData.base64EncodedString(options: [
      .lineLength64Characters, .endLineWithLineFeed,
    ])

    //INFO: Define static parts
    let header = "-----BEGIN CERTIFICATE REQUEST-----"
    let footer = "-----END CERTIFICATE REQUEST-----"

    //INFO: conjoin the parts
    let pemParts = [header, base64, footer]
    let pemString = pemParts.joined(separator: "\n")

    //INFO: Add an endline (primarily for print+copy+paste test inside a validator)
    return pemString + "\n"
  }

  private func buildDER() -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecReturnRef as String: true,
    ]

    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
      let privateKey = item as! SecKey?,
      let publicKey = SecKeyCopyPublicKey(privateKey),
      let pubKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
    else {
      logger.error("Key not found in enclave")
      return nil
    }

    var info = Data()
    info.append(contentsOf: [0x02, 0x01, 0x00])  // Version 0
    info.append(encodeSubject())
    info.append(encodePublicKeyInfo(pubKeyData))
    info.append(contentsOf: [0xA0, 0x00])  // Attributes empty

    let infoSequence = wrapSequence(info)

    var error: Unmanaged<CFError>?
    guard
      let signature = SecKeyCreateSignature(
        privateKey, .ecdsaSignatureMessageX962SHA256, infoSequence as CFData, &error) as Data?
    else {
      return nil
    }

    var final = Data()
    final.append(infoSequence)
    // OID for ecdsa-with-sha256 (1.2.840.10045.4.3.2)
    final.append(wrapSequence(Data([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])))
    // sign as bit-string
    var sigWithPadding = Data([0x00])
    sigWithPadding.append(signature)
    final.append(Data([0x03]) + encodeLength(sigWithPadding.count) + sigWithPadding)

    return wrapSequence(final)
  }

  private func encodePublicKeyInfo(_ pubKey: Data) -> Data {
    // AlgID: id-ecPublicKey (1.2.840.10045.2.1) + prime256v1 (1.2.840.10045.3.1.7)
    let algId = wrapSequence(
      Data([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])
        + Data([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
    )
    // key as bitstring
    var keyWithPadding = Data([0x00])
    keyWithPadding.append(pubKey)
    let keyData = Data([0x03]) + encodeLength(keyWithPadding.count) + keyWithPadding

    return wrapSequence(algId + keyData)
  }

  private func wrapSequence(_ data: Data) -> Data {
    return Data([0x30]) + encodeLength(data.count) + data
  }

  private func encodeLength(_ length: Int) -> Data {
    if length < 128 {
      return Data([UInt8(length)])
    } else {
      var temp = length
      var bytes = Data()
      while temp > 0 {
        bytes.insert(UInt8(temp & 0xff), at: 0)
        temp >>= 8
      }
      return Data([0x80 + UInt8(bytes.count)]) + bytes
    }
  }

  private func encodeSubject() -> Data {
    func encodeRDN(oid: [UInt8], value: String) -> Data {
      let valData = value.data(using: .utf8)!
      let stringType: UInt8 = 0x0c  // UTF8String
      let pair = wrapSequence(
        Data([0x06, UInt8(oid.count)]) + Data(oid) + Data([stringType])
          + encodeLength(valData.count) + valData)
      return Data([0x31]) + encodeLength(pair.count) + pair  // SET
    }

    var subject = Data()
    subject.append(encodeRDN(oid: [0x55, 0x04, 0x06], value: country))  // C
    subject.append(encodeRDN(oid: [0x55, 0x04, 0x08], value: state))  // S
    subject.append(encodeRDN(oid: [0x55, 0x04, 0x07], value: locality))  // L
    subject.append(encodeRDN(oid: [0x55, 0x04, 0x0a], value: organization))  // O
    subject.append(encodeRDN(oid: [0x55, 0x04, 0x0b], value: organizational_unit))  //OU
    subject.append(encodeRDN(oid: [0x55, 0x04, 0x03], value: commonName))  // CN
    subject.append(
      encodeRDN(
        oid: [
          0x2a,
          UInt8(0x86),
          0x48,
          UInt8(0x86),
          UInt8(0xf7),
          0x0d,
          0x01,
          0x09,
          0x01,
        ], value: email))
    return wrapSequence(subject)
  }
}
