import Foundation
import LocalAuthentication
import OSLog

class SignManager {

  //NOTE: One can notice that our biometry class is not called in this function
  //      This is by design, the key itself can only be used when biometrically authenticated
  //      this property is specified during key generation
  public func sign(data_to_sign: Data, tag: Data, context: LAContext) -> Data? {

    Logger.instance.log("Initiating signing process")

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
      Logger.instance.error("Private key not found. Keychain status: \(status)")
      return nil
    }

    var error: Unmanaged<CFError>?

    guard
      let signature = SecKeyCreateSignature(
        privateKey,
        .ecdsaSignatureDigestX962SHA256,
        data_to_sign as CFData,
        &error
      )
    else {
      let err = error?.takeRetainedValue()
      Logger.instance.error(
        "Signature inside secure enclave failed, error: \(err?.localizedDescription ?? "Unknown error", privacy: .public)"
      )
      return nil
    }

    Logger.instance.info("Data successfully signed with hardware key")
    return signature as Data

  }

  //INFO: Prepare document for signing
  private func prepareDocument(document: Data) -> Data? {
    return nil
  }

  //INFO: Inject the signature to the prepared document
  private func injectSignature(prepared_document: Data) -> Data? {
    return nil
  }

}
