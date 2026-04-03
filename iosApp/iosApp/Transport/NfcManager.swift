import CoreNFC
import Foundation
import OSLog
import SwiftUI

//INFO: Protocol definition for UI
protocol NFCManagerDelegate: AnyObject {
  func onNFCConnected()
  func onEngagementDataReceived(data: Data)
  func onNFCError(message: String)
}

class NFCManager: NSObject, NFCNDEFReaderSessionDelegate {

  static private let logger = Logger.category("NFCManager")

  //INFO: weak reference against memory leaks
  weak var delegate: NFCManagerDelegate?

  private var nfcSession: NFCNDEFReaderSession?

  public func startEngagement() {
    guard NFCNDEFReaderSession.readingAvailable else {
      delegate?.onNFCError(message: "NFC is not supported on this device :(")
      return
    }

    NFCManager.logger.log("Starting NFC scan")

    nfcSession = NFCNDEFReaderSession(delegate: self, queue: nil, invalidateAfterFirstRead: true)
    nfcSession?.alertMessage = "Přibližte telefon ke čtečce"
    nfcSession?.begin()
  }

  public func stopNFC() {
    NFCManager.logger.log("Stopping NFC transfer session")
    nfcSession?.invalidate()
    nfcSession = nil
  }

  // NOTE: - NFCNDEFReaderSessionDelegate methods

  //INFO: Called if the NFC transfer fails or is cancelled by the user
  func readerSession(_ session: NFCNDEFReaderSession, didInvalidateWithError error: Error) {
    if let readerError = error as? NFCReaderError,
      readerError.code != .readerSessionInvalidationErrorUserCanceled
    {
      NFCManager.logger.error("NFC Error: \(error.localizedDescription)")
      delegate?.onNFCError(message: error.localizedDescription)
    }
  }

  //INFO: this function is called when the phone successfully reads NDEF message from some other device
  func readerSession(_ session: NFCNDEFReaderSession, didDetectNDEFs messages: [NFCNDEFMessage]) {
    NFCManager.logger.info("NFC tag successfully read")
    delegate?.onNFCConnected()

    //TODO: Extract raw data from the first message
    if let firstRecord = messages.first?.records.first {
      let payload = firstRecord.payload
      delegate?.onEngagementDataReceived(data: payload)
    }
  }
}
