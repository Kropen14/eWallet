package cz.project.ewallet

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.fragment.app.FragmentActivity
import java.io.InputStream

class FileHandler {

        fun processSelectedFile(
                context: Context,
                uri: Uri?,
                enclave: EnclaveManager,
                onSignatureReady: (String) -> Unit
        ) {
                if (uri == null) {
                        Log.d("FileHandler", "User cancelled file selection")
                        return
                }

                Log.d("FileHandler", "Processing file URI: $uri")

                try {
                        // ContentResolver acts as a bridge to reach the data behind the URI
                        val inputStream: InputStream? = context.contentResolver.openInputStream(uri)

                        inputStream?.use { stream ->
                                // Read all bytes from the stream into a ByteArray
                                val bytes = stream.readBytes()
                                Log.d("FileHandler", "File successfully opened and read")
                                Log.d("FileHandler", "Total size: ${bytes.size} bytes")

                                val activity = context as? FragmentActivity
                                if (activity != null) {
                                        Log.d("FileHandler", "Starting biometric authentication")
                                        authenticateAndSign(
                                                activity,
                                                enclave,
                                                bytes,
                                                "document.pdf",
                                                onSignatureReady
                                        )
                                }
                        }
                } catch (e: Exception) {
                        Log.e("FileHandler", "Failed to read file: ${e.message}")
                }
        }

        fun saveContentAsFile(context: Context, uri: Uri?, content: String?) {
                if (uri == null) {
                        Log.d("FileHandler", "User cancelled the save dialog")
                        return
                }

                if (content == null) {
                        Log.e("FileHandler", "Content is null, nothing to save!")
                        return
                }

                Log.d("FileHandler", "Attempting to save file to URI: $uri")

                try {
                        context.contentResolver.openOutputStream(uri)?.use { outputStream ->
                                outputStream.write(content.toByteArray(Charsets.UTF_8))

                                Log.d("FileHandler", "Success! File successfully saved to disk")
                        }
                } catch (e: Exception) {
                        Log.e("FileHandler", "Failed to save file: ${e.message}")
                }
        }
}
