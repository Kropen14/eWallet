import LocalAuthentication
import OSLog

class Biometry {

  func authenticateUser(bio_message: String) async -> (success: Bool, err: Error?) {
    let context = LAContext()
    //INFO: disables fallback authentication with PIN
    context.localizedFallbackTitle = ""

    var error: NSError?

    Logger.instance.log("Setting up hardware enclave")
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {

      switch context.biometryType {

      case .faceID:
        Logger.instance.log("FaceID available !")
      case .touchID:
        Logger.instance.log("TouchID available !")
      case .none:
        Logger.instance.log(
          "ERROR: No biometric verification available, application cannot run properly !")
      @unknown default:
        Logger.instance.log("Unknown biometry type")
      }
    } else {
      let description = error?.localizedDescription ?? "Unknown error"
      Logger.instance.log("Biometry could not be set up properly : \(description)")
      return (false, error)
    }

    do {
      let success = try await context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics, localizedReason: bio_message)

      if success {
        Logger.instance.log("Biometric authentication resulted in success")
        return (true, nil)
      } else {
        Logger.instance.log("Biometric authentication failed!")
      }
    } catch let authError as LAError {
      Logger.instance.error(
        "Error during authentication : \(authError.localizedDescription, privacy: .public)")
      return (false, authError)
    } catch {
      Logger.instance.error(
        "Unknown error has occured : \(error.localizedDescription, privacy: .public)")
      return (false, error)
    }

    return (false, nil)
  }
}
