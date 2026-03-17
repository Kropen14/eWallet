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

            let certFromBundle: SecCertificate? = {
              guard let url = Bundle.main.url(forResource: "cert", withExtension: "der"),
                let data = try? Data(contentsOf: url)
              else {
                print("CHYBA: Soubor cert.der nebyl v aplikaci nalezen!")
                return nil
              }
              return SecCertificateCreateWithData(nil, data as CFData)
            }()

            guard let certData = certFromBundle else { return }

            //            guard
            //             let certData = signManager.findCertificate(
            //              tag: EnclaveManager.Constants.localDeviceTag)
            //         else {
            //              logger.error(
            //               "Failed to fetch certificate for \(EnclaveManager.Constants.localDeviceTag, privacy: .public)"
            //             )
            //return
            // }

            if let jadesData = signManager.signAsJAdES(
              originalDocument: picked.data,
              fileName: picked.name,
              tag: EnclaveManager.Constants.localDeviceTag,
              pubKeyData: pubKeyData,
              context: context,
              userCert: certData)
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
