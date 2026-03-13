import Foundation
import LocalAuthentication
import OSLog

class FileHandler {

  public func importFile() -> Data? {

    let fileManager = FileManager()

    guard
      let documentsDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first
    else {
      return nil
    }

    return nil
  }

  public func saveModifiedFile(file: Data) -> Data? {
    return nil
  }
}
