import Shared
import SwiftUI

struct ContentView: View {
  // Vytvoříme si instanci tvého manažeru
  let enclaveManager = EnclaveManager()

  var body: some View {
    VStack {
      Button("Test Secure Enclave & FaceID") {
        enclaveManager.setup()
        enclaveManager.run()
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
