import LocalAuthentication
import OSLog
import Shared
import SwiftUI

struct ContentView: View {
  let enclaveManager = EnclaveManager()
  let signManager = SignManager()
  let biometry = Biometry()

  var body: some View {
    VStack {

      Button("Generate keys & Set up enclave") {
        enclaveManager.run()
      }
      .padding()
      .background(Color.blue)
      .foregroundColor(.white)
      .cornerRadius(10)

      Button("Test Sign & FaceID") {
        Task {
          let message = "Potvrzuji něco".data(using: .utf8)!

          let context = LAContext()
          context.localizedReason = "Podepisujete něco pro eWallet "
          context.localizedFallbackTitle = ""

          if let signature = signManager.sign(
            data_to_sign: message,
            tag: EnclaveManager.Constants.localDeviceTag,
            context: context
          ) {
            Logger.instance.log("We have a signature with lenght of : \(signature.count) bytes")
          } else {
            Logger.instance.log("Signature either failed or was canceled")
          }
        }
      }
      .padding()
      .background(Color.blue)
      .foregroundColor(.white)
      .cornerRadius(10)
    }
  }
}

struct ContentView_Previews: PreviewProvider {
  static var previews: some View {
    ContentView()
  }
}
