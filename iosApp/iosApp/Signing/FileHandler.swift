import Foundation
import LocalAuthentication
import OSLog

class FileHandler {

  private let logger = Logger.category("FileHandler")
  private var fileType: String = "_signed.jades.json"
  let fileManager = FileManager.default

  public func saveSignedFile(data: Data, originalName: String) -> URL? {

    guard
      let documentsDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first
    else {
      logger.error("Failed to locate 'Documents' directory")
      return nil
    }

    let file_name = "\(originalName)" + fileType
    let file_url = documentsDirectory.appendingPathComponent(file_name)

    do {

      if fileManager.fileExists(atPath: file_url.path) {
        try fileManager.removeItem(at: file_url)
        logger.info("Removed existing file for rewrite")
      }

      try data.write(to: file_url, options: .atomic)
      logger.info("File successfully saved at: \(file_url.path())")
      return file_url
    } catch {

      logger.error("Error during file saving: \(error.localizedDescription)")
      return nil
    }
  }

  public func handlePickedFile(at url: URL) -> (data: Data, name: String)? {
    //INFO: Request access to external files
    guard url.startAccessingSecurityScopedResource() else {
      logger.error("The app doesn't have permissions for this file")
      return nil
    }
    defer { url.stopAccessingSecurityScopedResource() }

    do {
      let data = try Data(contentsOf: url)
      let name = url.deletingPathExtension().lastPathComponent
      return (data, name)
    } catch {
      logger.error("Error occured when reading the data: \(error.localizedDescription)")
      return nil
    }

  }
}
