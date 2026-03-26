import SwiftUI

@main
struct iOSApp: App {

  init() {
    BLEPeripheralManager.shared.start()
  }

  var body: some Scene {
    WindowGroup {
      ContentView()
    }
  }
}

