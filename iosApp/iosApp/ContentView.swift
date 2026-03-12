import OSLog
import Shared
import SwiftUI

struct ContentView: View {
  // Vytvoříme si instanci tvého manažeru
  let enclaveManager = EnclaveManager()
  let biometry = Biometry()

  var body: some View {
    VStack {
      Button("Test Secure Enclave & FaceID") {
        enclaveManager.setup()
        enclaveManager.run()
        Task {
          let result = await biometry.authenticateUser(bio_message: "Přihlaste se do eWallet")

          if result.success {
            Logger.instance.info("FaceID okno úspěšně prošlo!")
          } else {
            Logger.instance.error("Uživatel to zrušil nebo FaceID selhalo.")
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
