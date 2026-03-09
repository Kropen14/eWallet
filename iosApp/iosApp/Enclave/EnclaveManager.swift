import CryptoKit
import Foundation
import LocalAuthentication
import Security

class EnclaveManager {

    private enum Constants {
        static let qesAuthTag = "cz.project.ewallet.qes_auth_key".data(using: .utf8)!
        static let localDeviceTag = "cz.project.ewallet.local_device_key".data(using: .utf8)!
        static let biometricTimeout: TimeInterval = 30
    }

    func setup() {
    }

    func generateLocalDeviceKey() {
    }

    func generateQesAuthKey() {
        generateKey(tag: Constants.qesAuthTag, requireAuth: true)
    }

    private func generateKey(tag: Data, requireAuth: Bool) {
        var error: Unmanaged<CFError>?

        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &error
        )

        guard let control = accessControl else { return }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: control,
            ] as [String: Any],
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let err = error?.takeRetainedValue()
            print("Error during key generation \(err?.localizedDescription ?? " Unknown error ")")
            return
        }
        print("Key successfully generated inside Secure Enclave")
    }

    func getAttestationData(tag: String) -> Data? {
        return nil
    }

    func getSignatureContext() -> LAContext {
        return LAContext()
    }

    func getPubKey(tag: String) -> Data? {
        return nil
    }
}
