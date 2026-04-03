import AuthenticationServices
import Foundation
import LocalAuthentication
import OSLog
import Shared
import SwiftUI

//WARN: May break in the future if swift implements this differently
extension URL: Identifiable {
  public var id: String { self.absoluteString }
}

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

  // INFO: Inicializace ViewModelu pro obsluhu NFC
  @StateObject private var nfcViewModel = NFCViewModel()

  var body: some View {
    VStack {
      Button("Generate keys & Set up enclave") {
        enclaveManager.run()
      }
      .padding()
      .background(Color.red)
      .foregroundColor(.white)
      .cornerRadius(10)

      Button("Contact BankiD & generateCSR") {
        Task {
          await performWebLogin()
        }
      }
      .padding()
      .background(Color.mint)
      .foregroundColor(.white)
      .cornerRadius(10)

      Button("Sign document from files") {
        isImporting = true
      }
      .padding()
      .background(Color.indigo)
      .foregroundColor(.white)
      .cornerRadius(10)

      // INFO: Nové tlačítko pro testování NFC
      Button("Test NFC Scanner") {
        nfcViewModel.startScanning()
      }
      .padding()
      .background(Color.orange)
      .foregroundColor(.white)
      .cornerRadius(10)

      // INFO: Zobrazení aktuálního stavu NFC (hlášky z delegáta)
      Text(nfcViewModel.statusMessage)
        .font(.caption)
        .foregroundColor(.secondary)
        .padding(.top, 4)

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
              guard let url = Bundle.main.url(forResource: "new_cert", withExtension: "der"),
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
      //WARN: Change after going to production
      let ngrokCallback = "https://patrina-noninterpretive-uninterestingly.ngrok-free.dev"
      let loginPortalURL = try await networkManager.getBankIdLoginURL(ngrokUrl: ngrokCallback)

      guard let url = URL(string: loginPortalURL) else { return }

      let callbackUrl = try await webAuthSession.authenticate(
        using: url,
        callbackURLScheme: "ewallet"  //INFO: Deeplink project setting dependent
      )

      logger.log("Successfully returned to app: \(callbackUrl.absoluteString)")

      guard let components = URLComponents(url: callbackUrl, resolvingAgainstBaseURL: false),
        let queryItems = components.queryItems,
        let token = queryItems.first(where: { $0.name == "token" })?.value
      else {
        logger.error("Token not found in return address")
        return
      }

      if let userData = JWTDecoder.decodePayload(token: token, as: UserData.self) {
        logger.log("Extracted userData for: \(userData.commonName)")

        generateCSR(from: userData)

      } else {
        logger.error("Unable to extract user data")
      }

    } catch {
      logger.error("Login failed: \(error.localizedDescription)")
    }
  }

  private func generateCSR(from userData: UserData) {
    let csrEngine = CSREngine(tag: EnclaveManager.Constants.localDeviceTag, userData: userData)

    if let pemString = csrEngine.buildPEM() {
      logger.log("Successfully generated a CSR for the user")
      let url = FileManager.default.temporaryDirectory.appendingPathComponent("request.csr")

      do {
        try pemString.write(to: url, atomically: true, encoding: .utf8)
        self.itemURL = url
      } catch {
        logger.error("Failed to save CSR: \(error.localizedDescription)")
      }
    } else {
      logger.error("Error during PEM build in CSREngine layer")
    }
  }
}

// ObservableObject umožňuje SwiftUI sledovat změny v této třídě
class NFCViewModel: ObservableObject, NFCManagerDelegate {

  // @Published proměnné automaticky překreslí UI, když se jejich hodnota změní
  @Published var statusMessage: String = "Připraveno ke čtení"
  @Published var isScanning: Bool = false

  // Instance tvého NFC manažera
  private var nfcManager = NFCManager()

  init() {
    // Nastavíme tento ViewModel jako delegáta pro NFCManager
    nfcManager.delegate = self
  }

  func startScanning() {
    statusMessage = "Přiložte telefon..."
    isScanning = true
    nfcManager.startEngagement()
  }

  // MARK: - NFCManagerDelegate implementace

  func onNFCConnected() {
    // UI aktualizace MUSÍ probíhat na hlavním vlákně (Main Thread)
    DispatchQueue.main.async {
      self.statusMessage = "NFC tag detekován, probíhá čtení..."
    }
  }

  func onEngagementDataReceived(data: Data) {
    DispatchQueue.main.async {
      self.isScanning = false
      self.statusMessage = "Úspěch! Přijato \(data.count) bytů dat."

      // TODO: Tady vezmeš 'data' a pošleš je do svého Kotlin Multiplatform
      // modulu k rozparsování (např. CBOR dekodér pro mDL engagement)
    }
  }

  func onNFCError(message: String) {
    DispatchQueue.main.async {
      self.isScanning = false
      self.statusMessage = "NFC selhalo: \(message)"
    }
  }
}
