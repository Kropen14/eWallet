import CoreBluetooth
import Foundation
import OSLog

class BLEPeripheralManager: NSObject, CBPeripheralManagerDelegate, ObservableObject {

  static let shared = BLEPeripheralManager()

  private var peripheralManager: CBPeripheralManager?
  private let logger = Logger.category("BLEManager")

  @Published var permissionGranted: Bool = false

  private override init() {
    super.init()
    self.peripheralManager = CBPeripheralManager(delegate: self, queue: nil)
  }

  func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
    switch peripheral.state {
    case .poweredOn:
      logger.log("Bluetooth is powered on and ready to advertise mDL.")
      self.permissionGranted = true
    case .unauthorized:
      logger.log("User denied Bluetooth permission.")
      self.permissionGranted = false
    case .unsupported:
      logger.log("This device does not support Bluetooth LE.")
    case .poweredOff:
      logger.log("Bluetooth is turned off in Settings.")
    case .resetting, .unknown:
      logger.log("Bluetooth state unknown/resetting.")
    @unknown default:
      logger.log("A new state was added that we don't handle.")
    }
  }

  func start() {
    logger.log("BLE manager started")
  }

}
