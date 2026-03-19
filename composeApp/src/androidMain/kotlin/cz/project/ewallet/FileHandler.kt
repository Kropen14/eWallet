package cz.project.ewallet

import android.content.Context
import android.net.Uri
import android.util.Log
import java.io.InputStream

class FileHandler {

        fun processSelectedFile(context: Context, uri: Uri?) {
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
                        }
                } catch (e: Exception) {
                        Log.e("FileHandler", "Failed to read file: ${e.message}")
                }
        }
}
