package cz.project.ewallet

import android.net.Uri
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeContentPadding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import java.security.cert.X509Certificate

@Composable
@Preview
fun App() {
        Log.d("ContentView", "Initializing App Composable")

        val context = LocalContext.current

        // Initialize EnclaveManager
        val enclave = remember {
                Log.d("ContentView", "Setting up EnclaveManager")
                EnclaveManager().apply { setup() }
        }

        // State management
        var keyExists by remember { mutableStateOf(enclave.hasKey(EnclaveManager.ALIAS_QES_AUTH)) }
        var statusMessage by remember {
                mutableStateOf(if (keyExists) "Key found!" else "Key not found")
        }
        var attestationInfo by remember { mutableStateOf<String?>(null) }

        // Logic for processing files in a separate class
        val fileHandler = remember { FileHandler() }

        // State to temporarily hold the JSON signature until the user picks a save location
        var pendingSignature by remember { mutableStateOf<String?>(null) }

        // Launcher for system file picker
        val pickerLauncher =
                rememberLauncherForActivityResult(
                        contract = ActivityResultContracts.OpenDocument(),
                        onResult = { uri: Uri? ->
                                Log.d("ContentView", "File picker result received: $uri")
                                Log.d("TEMP", "$context")

                                fileHandler.processSelectedFile(context, uri, enclave) {
                                        jsonSignature ->
                                        Log.d(
                                                "ContentView",
                                                "Received JAdES signature from FileHandler"
                                        )
                                        pendingSignature = jsonSignature
                                }
                        }
                )

        // Launcher for creating/saving a document
        val saveLauncher =
                rememberLauncherForActivityResult(
                        contract = ActivityResultContracts.CreateDocument("application/json"),
                        onResult = { uri: Uri? ->
                                Log.d("ContentView", "Save picker result received: $uri")
                                // Write the JSON to the chosen location
                                fileHandler.saveContentAsFile(context, uri, pendingSignature)
                                // Clear the state so it's ready for next time
                                pendingSignature = null
                        }
                )

        // Effect to automatically trigger the save dialog when we get a new signature
        LaunchedEffect(pendingSignature) {
                if (pendingSignature != null) {
                        Log.d("ContentView", "New signature generated, prompting user to save...")
                        // Suggest a default filename to the user
                        saveLauncher.launch("signature_jades.json")
                }
        }

        // Side effect to handle attestation chain fetching when key state changes
        // This prevents infinite logging loops during recomposition
        LaunchedEffect(keyExists) {
                if (keyExists) {
                        Log.d(
                                "ContentView",
                                "Key exists, fetching attestation chain for UI display"
                        )
                        val chain = enclave.getAttestationChain(EnclaveManager.ALIAS_QES_AUTH)
                        if (chain != null && chain.isNotEmpty()) {
                                attestationInfo =
                                        chain
                                                .mapIndexed { index, cert ->
                                                        val x509 = cert as? X509Certificate
                                                        "Cert [$index]:\n${x509?.subjectDN?.name}"
                                                }
                                                .joinToString(separator = "\n\n")
                                Log.d(
                                        "ContentView",
                                        "Attestation chain successfully parsed. Items: ${chain.size}"
                                )
                        } else {
                                attestationInfo = "Attestation chain not found."
                                Log.w(
                                        "ContentView",
                                        "Key exists but getAttestationChain returned null or empty"
                                )
                        }
                } else {
                        attestationInfo = null
                }
        }

        MaterialTheme {
                Column(
                        modifier =
                                Modifier.background(MaterialTheme.colorScheme.primaryContainer)
                                        .safeContentPadding()
                                        .fillMaxSize(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                ) {
                        Text(
                                text = "Enclave state: $statusMessage",
                                style = MaterialTheme.typography.headlineSmall,
                                modifier = Modifier.padding(bottom = 16.dp)
                        )

                        // Button: Select File
                        Button(
                                onClick = {
                                        Log.d("ContentView", "User clicked 'Select file' button")
                                        pickerLauncher.launch(arrayOf("application/pdf"))
                                },
                                modifier = Modifier.padding(8.dp)
                        ) { Text("Select a file for signing") }

                        // Button: Generate Key
                        Button(
                                onClick = {
                                        Log.d("ContentView", "User clicked 'Generate key' button")
                                        try {
                                                enclave.generateQesAuthKey()
                                                keyExists = true
                                                statusMessage = "Key successfully generated"
                                                Log.d("ContentView", "Key generation successful")
                                        } catch (e: Exception) {
                                                statusMessage = "Error: ${e.message}"
                                                Log.e(
                                                        "ContentView",
                                                        "Exception during key generation: ${e.message}"
                                                )
                                        }
                                },
                                modifier = Modifier.padding(8.dp)
                        ) { Text("Generate key") }

                        // Button: Delete Key (Conditional)
                        if (keyExists) {
                                Button(
                                        onClick = {
                                                Log.d(
                                                        "ContentView",
                                                        "User clicked 'Delete key' button"
                                                )
                                                try {
                                                        enclave.deleteKey(
                                                                EnclaveManager.ALIAS_QES_AUTH
                                                        )
                                                        keyExists = false
                                                        statusMessage = "Key deleted from Keystore"
                                                        Log.d(
                                                                "ContentView",
                                                                "Key successfully deleted"
                                                        )
                                                } catch (e: Exception) {
                                                        statusMessage =
                                                                "Error deleting key: ${e.message}"
                                                        Log.e(
                                                                "ContentView",
                                                                "Exception during key deletion: ${e.message}"
                                                        )
                                                }
                                        },
                                        modifier = Modifier.padding(8.dp),
                                        colors =
                                                androidx.compose.material3.ButtonDefaults
                                                        .buttonColors(
                                                                containerColor =
                                                                        MaterialTheme.colorScheme
                                                                                .error
                                                        )
                                ) { Text("Delete key") }
                        }

                        // Attestation Info Display
                        attestationInfo?.let { info ->
                                Text(
                                        text = "Attestation Chain:\n$info",
                                        modifier = Modifier.padding(top = 16.dp),
                                        style = MaterialTheme.typography.bodySmall
                                )
                        }
                }
        }
}
