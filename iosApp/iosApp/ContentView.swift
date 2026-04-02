import AuthenticationServices
import LocalAuthentication
import OSLog
import Shared
import SwiftUI

struct ContentView: View {
  let enclaveManager = EnclaveManager()
  let signManager = SignManager()
  let biometry = Biometry()
  let logger = Logger.category("ContentView")
  let networkManager = NetworkManager()

  @State private var isImporting = false
  @State private var itemURL: URL? = nil
  @Environment(\.webAuthenticationSession) private var webAuthSession

  let fileHandler = FileHandler()

  var body: some View {
    VStack {
      Button("Generate keys & Set up enclave") {
        enclaveManager.run()
      }
      .padding()
      .background(Color.red)
      .foregroundColor(.white)
      .cornerRadius(10)

      Button("Generate & Share CSR") {
        generateAndShareCSR(
          tag: EnclaveManager.Constants.localDeviceTag, commonName: "John Doe",
          organization: "Signosoft", organizational_unit: "eWallet",
          locality: "Prague", state: "Prague", country: "CZ", email: "john.doe@hotmail.com")
      }
      .padding()
      .background(Color.green)
      .foregroundColor(.white)
      .cornerRadius(10)

      Button("Contact BankiD") {
        Task {
          await performWebLogin()
        }
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
    ) { result in
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
                logger.error(" cert.der file not found")
                return nil
              }
              return SecCertificateCreateWithData(nil, data as CFData)
            }()

            //WARN: Use the proper certificate recieved from the CA after submitting CSR
            guard let certData = certFromBundle else { return }

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
    .sheet(item: $itemURL) {
      url in ShareSheet(items: [url])
    }
  }

  private func performWebLogin() async {
    do {

      //WARN: Has to be changed to the current grok callback url
      let ngrokCallback = "https://patrina-noninterpretive-uninterestingly.ngrok-free.dev"
      let loginPortalURL = try await networkManager.getBankIdLoginURL(ngrokUrl: ngrokCallback)

      guard let url = URL(string: loginPortalURL) else { return }

      //  ASWebAuthenticationSession will wait for "ewallet://"
      // When your Node.js server redirects to ewallet://auth?status=success,
      // this call returns.
      let callbackUrl = try await webAuthSession.authenticate(
        using: url,
        callbackURLScheme: "ewallet"
      )

      //  Handle the successful snap-back
      logger.log("Successfully returned to app: \(callbackUrl.absoluteString)")

      // At this point, Signosoft has already POSTed the JSON data
      // to your local Node.js server.

    } catch {
      logger.error("Login failed: \(error.localizedDescription)")
    }
  }

  public func generateAndShareCSR(
    tag: Data, commonName: String, organization: String, organizational_unit: String,
    locality: String, state: String, country: String, email: String
  ) {
    let csr = CSREngine(
      tag: tag, commonName: commonName, organization: organization,
      organizational_unit: organizational_unit,
      locality: locality, state: state, country: country, email: email)

    if let pemString = csr.buildPEM() {
      logger.log("CSR Successfully generated")
      let url = FileManager.default.temporaryDirectory.appendingPathComponent("request.csr")

      do {
        try pemString.write(to: url, atomically: true, encoding: .utf8)
        self.itemURL = url
      } catch {
        logger.error("Failed to save CSR: \(error.localizedDescription)")
      }
    }
  }
}

//WARN: May break in the future if swift implements this differently
extension URL: Identifiable {
  public var id: String { self.absoluteString }
}
