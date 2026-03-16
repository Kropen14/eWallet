import LocalAuthentication
import OSLog

class Biometry {

  private let logger = Logger.category("Biometry")

  func authenticateUser(bio_message: String) async -> (success: Bool, err: Error?) {
    let context = LAContext()
    //INFO: disables fallback authentication with PIN
    context.localizedFallbackTitle = ""

    var error: NSError?

    logger.log("Setting up hardware enclave")
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {

      switch context.biometryType {

      case .faceID:
        logger.log("FaceID available !")
      case .touchID:
        logger.log("TouchID available !")
      case .none:
        logger.log(
          "ERROR: No biometric verification available, application cannot run properly !")
      @unknown default:
        logger.log("Unknown biometry type")
      }
    } else {
      let description = error?.localizedDescription ?? "Unknown error"
      logger.log("Biometry could not be set up properly : \(description)")
      return (false, error)
    }

    do {
      let success = try await context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics, localizedReason: bio_message)

      if success {
        logger.log("Biometric authentication resulted in success")
        return (true, nil)
      } else {
        logger.log("Biometric authentication failed!")
      }
    } catch let authError as LAError {
      logger.error(
        "Error during authentication : \(authError.localizedDescription, privacy: .public)")
      return (false, authError)
    } catch {
      logger.error(
        "Unknown error has occured : \(error.localizedDescription, privacy: .public)")
      return (false, error)
    }

    return (false, nil)
  }
}
