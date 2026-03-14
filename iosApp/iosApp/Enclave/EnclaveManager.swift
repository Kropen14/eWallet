import CryptoKit
import DeviceCheck
import Foundation
import LocalAuthentication
import OSLog
import Security

//INFO: Single global Logger.instance instance
extension Logger {
  static let instance = Logger(subsystem: "cz.project.ewallet", category: "Security")
}

class EnclaveManager {

  public enum Constants {
    static let qesAuthTag = "cz.project.ewallet.qes_auth_key".data(using: .utf8)!
    static let localDeviceTag = "cz.project.ewallet.local_device_key".data(using: .utf8)!
    static let biometricTimeout: TimeInterval = 30
  }

  public func run() {
    let keys = checkKeyExistence()

    for (tag, exists) in keys {
      if !exists {
        Logger.instance.log(
          "Generating key \(String(data: tag, encoding: .utf8)!,  privacy: .public)) inside hardware enclave"
        )
        generateKey(tag: tag, requireAuth: true)
      }
    }
  }

  private func checkKeyExistence() -> [(Data, Bool)] {
    let keys = [Constants.qesAuthTag, Constants.localDeviceTag]
    var results: [(Data, Bool)] = []
    for tag in keys {
      if getPubKey(tag: tag) != nil {
        Logger.instance.log(
          "Key for \(String(data: tag, encoding: .utf8)!, privacy: .public) already exists")
        results.append((tag, true))
      } else {
        Logger.instance.log(
          "Key for \(String(data: tag, encoding: .utf8)!, privacy: .public) does not exist and will be created"
        )
        results.append((tag, false))
      }

    }
    return results
  }

  private func generateKey(tag: Data, requireAuth: Bool) {
    var error: Unmanaged<CFError>?

    let flags: SecAccessControlCreateFlags =
      requireAuth ? [.biometryCurrentSet, .privateKeyUsage] : []

    guard
      let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        &error
      )
    else {
      Logger.instance.log("Error, can not create Acess Control ruleset")
      return
    }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessControl as String: accessControl,
        kSecAttrCanSign as String: true,
      ] as [String: Any],
    ]

    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      let err = error?.takeRetainedValue()
      Logger.instance.log(
        "Error during key generation \(err?.localizedDescription ?? " Unknown error ")")
      return
    }
    Logger.instance.log("Key successfully generated inside Secure Enclave")
  }

  public func getAttestationData(challengeFromServer: Data) async -> (
    keyId: String, attestation: Data
  )? {
    let service = DCAppAttestService.shared

    guard service.isSupported else {
      Logger.instance.log("Error: App attest service is not supported on the current device")
      return nil
    }

    do {
      let keyId = try await service.generateKey()  //INFO: Generate key for attestation service

      let clientDataHash = Data(SHA256.hash(data: challengeFromServer))  //INFO: Prepare a challenge for the apple verification server

      let attestationObject = try await service.attestKey(keyId, clientDataHash: clientDataHash)  //INFO: Apple server communication, ret: CBOR

      return (keyId, attestationObject)

    } catch {
      Logger.instance.log("Error during attestation: \(error.localizedDescription)")
      return nil
    }
  }

  public func getSignatureContext() -> LAContext {
    return LAContext()
  }

  public func getPubKey(tag: Data) -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
      kSecReturnRef as String: true,  //INFO: We want to return a reference to the key
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)

    //INFO: End if no key was found
    guard status == errSecSuccess, let keyRef = item as! SecKey? else {
      return nil
    }

    //INFO: Get the public key out of the private one
    guard let publicKey = SecKeyCopyPublicKey(keyRef) else {
      return nil
    }

    var error: Unmanaged<CFError>?
    return SecKeyCopyExternalRepresentation(publicKey, &error) as Data?

  }

}
