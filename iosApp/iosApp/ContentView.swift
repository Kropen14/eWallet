import LocalAuthentication
import OSLog
import Shared
import SwiftUI

struct ContentView: View {
  let enclaveManager = EnclaveManager()
  let signManager = SignManager()
  let biometry = Biometry()
  let logger = Logger.category("ContentView")

  @State private var isImporting = false
  let fileHandler = FileHandler()

  var body: some View {
    VStack {

      Button("Generate keys & Set up enclave") {
        enclaveManager.run()
      }
      .padding()
      .background(Color.blue)
      .foregroundColor(.white)
      .cornerRadius(10)

      Button("Sign document from files") {
        isImporting = true
      }
      .padding()
      .background(Color.blue)
      .foregroundColor(.white)
      .cornerRadius(10)
    }
    .fileImporter(
      isPresented: $isImporting,
      allowedContentTypes: [.pdf],
      allowsMultipleSelection: false
    ) {
      result in
      switch result {
      case .success(let urls):
        guard let selectedUrl = urls.first else { return }
        if let picked = fileHandler.handlePickedFile(at: selectedUrl) {
          Task {
            let context = LAContext()
            context.localizedReason = "Signing file: \(picked.name)"
            context.localizedFallbackTitle = ""

            //INFO: get pubkey from enclave
            guard
              let pubKeyData = enclaveManager.getPubKey(
                tag: EnclaveManager.Constants.localDeviceTag)
            else {
              logger.error("Failed to load pubkey")
              return
            }

            if let jadesData = signManager.signAsJAdES(
              originalDocument: picked.data,
              fileName: picked.name,
              tag: EnclaveManager.Constants.localDeviceTag,
              pubKeyData: pubKeyData,
              context: context)
            {
              if let savedURL = fileHandler.saveSignedFile(
                data: jadesData, originalName: picked.name)
              {
                logger.log(
                  "JAdES signature saved at: \(savedURL.lastPathComponent, privacy: .public)")
              }
            } else {
              logger.error("Signing process failed")
            }
          }
        }
      case .failure(let error):
        logger.error("Selection failed \(error.localizedDescription)")
      }
    }
  }
}

struct ContentView_Previews: PreviewProvider {
  static var previews: some View {
    ContentView()
  }
}
