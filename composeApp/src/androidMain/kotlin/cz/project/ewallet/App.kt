package cz.project.ewallet

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeContentPadding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import java.io.File

@Composable
@Preview
fun App() {
    val TAG = "App"
    Log.d(TAG, "Initializing App Composable")

    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    // Initialize managers
    val enclave = remember {
        Log.d(TAG, "Setting up EnclaveManager")
        EnclaveManager().apply { setup() }
    }

    val networkManager = remember { NetworkManager() }
    val fileHandler = remember { FileHandler() }

    // State management
    var statusMessage by remember { mutableStateOf("Ready") }
    var pendingSignature by remember { mutableStateOf<String?>(null) }
    var pendingCSR by remember { mutableStateOf<String?>(null) }

    // Observe BankID token from deep link
    val bankIdToken by bankIdTokenFlow.collectAsState()

    // Decode user data from token when available
    val userData = remember(bankIdToken) {
        bankIdToken?.let { token ->
            Log.d(TAG, "BankID token received, decoding...")
            JWTDecoder.decodePayload(token)?.also {
                Log.d(TAG, "User data extracted for: ${it.commonName}")
            }
        }
    }

    // Generate CSR when user data is available
    LaunchedEffect(userData) {
        userData?.let { user ->
            Log.d(TAG, "User data available, will generate CSR for: ${user.commonName}")
            statusMessage = "User authenticated: ${user.commonName}"
        }
    }

    // Bluetooth permissions launcher
    val bluetoothPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT
        )
    } else {
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) { permissionsMap ->
        val allGranted = permissionsMap.values.all { it }
        if (allGranted) {
            Log.d(TAG, "All Bluetooth/NFC permissions granted")
        } else {
            Log.w(TAG, "Some permissions were denied")
        }
    }

    // Request permissions on startup
    LaunchedEffect(Unit) {
        Log.d(TAG, "Requesting Bluetooth permissions on startup")
        permissionLauncher.launch(bluetoothPermissions)
    }

    // File picker for signing documents
    val pickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
        onResult = { uri: Uri? ->
            Log.d(TAG, "File picker result received: $uri")
            fileHandler.processSelectedFile(context, uri, enclave) { jsonSignature ->
                Log.d(TAG, "Received JAdES signature from FileHandler")
                pendingSignature = jsonSignature
            }
        }
    )

    // Save launcher for CSR
    val csrSaveLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/x-pem-file"),
        onResult = { uri: Uri? ->
            Log.d(TAG, "CSR save picker result received: $uri")
            pendingCSR?.let { csr ->
                fileHandler.saveContentAsFile(context, uri, csr)
                pendingCSR = null
                statusMessage = "CSR saved successfully"
            }
        }
    )

    // Save launcher for signed documents
    val signatureSaveLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json"),
        onResult = { uri: Uri? ->
            Log.d(TAG, "Signature save picker result received: $uri")
            pendingSignature?.let { signature ->
                fileHandler.saveContentAsFile(context, uri, signature)
                pendingSignature = null
                statusMessage = "Signature saved successfully"
            }
        }
    )

    // Trigger save dialog when pending signature is set
    LaunchedEffect(pendingSignature) {
        pendingSignature?.let {
            Log.d(TAG, "Pending signature detected, launching save dialog")
            signatureSaveLauncher.launch("signed_document.json")
        }
    }

    // Trigger save dialog when pending CSR is set
    LaunchedEffect(pendingCSR) {
        pendingCSR?.let {
            Log.d(TAG, "Pending CSR detected, launching save dialog")
            csrSaveLauncher.launch("request.csr")
        }
    }

    // UI Layout
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .safeContentPadding()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically)
    ) {
        // Status message
        Text(
            text = statusMessage,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onBackground
        )

        // Button 1: Generate keys & Set up enclave
        Button(
            onClick = {
                Log.d(TAG, "User clicked 'Generate keys & Set up enclave' button")
                try {
                    enclave.generateQesAuthKey()
                    enclave.generateLocalDeviceKey()
                    statusMessage = "Keys successfully generated in enclave"
                    Log.d(TAG, "Key generation successful")
                } catch (e: Exception) {
                    statusMessage = "Error: ${e.message}"
                    Log.e(TAG, "Exception during key generation: ${e.message}")
                }
            },
            modifier = Modifier.padding(8.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color.Red)
        ) {
            Text("Generate keys & Set up enclave", color = Color.White)
        }

        // Button 2: Contact BankID & generateCSR
        Button(
            onClick = {
                Log.d(TAG, "User clicked 'Contact BankID & generateCSR' button")
                coroutineScope.launch {
                    performBankIDLogin(
                        networkManager = networkManager,
                        context = context,
                        onError = { error ->
                            statusMessage = "BankID login failed: $error"
                            Log.e(TAG, "BankID login failed: $error")
                        }
                    )
                }
            },
            modifier = Modifier.padding(8.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00BFA5))
        ) {
            Text("Contact BankID & generateCSR", color = Color.White)
        }

        // Button 3: Generate CSR (only shown when user data is available)
        userData?.let { user ->
            Button(
                onClick = {
                    Log.d(TAG, "User clicked 'Generate CSR' button")
                    val activity = context as? FragmentActivity
                    if (activity != null) {
                        generateCSRWithBiometrics(
                            activity = activity,
                            enclave = enclave,
                            userData = user,
                            onSuccess = { pemString ->
                                pendingCSR = pemString
                                statusMessage = "CSR generated successfully"
                            },
                            onError = { error ->
                                statusMessage = "CSR generation failed: $error"
                                Log.e(TAG, "CSR generation failed: $error")
                            }
                        )
                    }
                },
                modifier = Modifier.padding(8.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6200EA))
            ) {
                Text("Generate & Save CSR", color = Color.White)
            }
        }

        // Button 4: Sign document from files
        Button(
            onClick = {
                Log.d(TAG, "User clicked 'Sign document from files' button")
                pickerLauncher.launch(arrayOf("application/pdf"))
            },
            modifier = Modifier.padding(8.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3F51B5))
        ) {
            Text("Sign document from files", color = Color.White)
        }

        // Delete keys button (only show if keys exist)
        if (enclave.hasKey(EnclaveManager.ALIAS_LOCAL_DEVICE)) {
            Button(
                onClick = {
                    Log.d(TAG, "User clicked 'Delete keys' button")
                    try {
                        enclave.deleteKey(EnclaveManager.ALIAS_QES_AUTH)
                        enclave.deleteKey(EnclaveManager.ALIAS_LOCAL_DEVICE)
                        statusMessage = "Keys deleted from Keystore"
                        Log.d(TAG, "Keys successfully deleted")
                    } catch (e: Exception) {
                        statusMessage = "Error deleting keys: ${e.message}"
                        Log.e(TAG, "Exception during key deletion: ${e.message}")
                    }
                },
                modifier = Modifier.padding(8.dp),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) {
                Text("Delete Keys")
            }
        }
    }
}

/**
 * Performs BankID login flow
 * Mirrors the iOS performWebLogin() function
 */
private suspend fun performBankIDLogin(
    networkManager: NetworkManager,
    context: android.content.Context,
    onError: (String) -> Unit
) {
    val TAG = "performBankIDLogin"
    
    try {
        // WARN: Change after going to production
        val ngrokCallback = "https://patrina-noninterpretive-uninterestingly.ngrok-free.dev"
        
        Log.d(TAG, "Getting BankID login URL...")
        val loginPortalURL = networkManager.getBankIdLoginURL(ngrokCallback)
        
        Log.d(TAG, "Opening browser with URL: $loginPortalURL")
        
        // Open BankID portal in browser
        // The browser will redirect back to the app via deep link (ewallet://auth?token=...)
        val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(loginPortalURL))
        context.startActivity(browserIntent)
        
        // The token will be caught by MainActivity's handleIntent() and stored in bankIdTokenFlow
        Log.d(TAG, "Browser launched, waiting for callback...")
        
    } catch (e: Exception) {
        Log.e(TAG, "Login failed: ${e.message}")
        onError(e.message ?: "Unknown error")
    }
}

/**
 * Generates CSR with biometric authentication
 * Mirrors the iOS generateCSR() function
 */
private fun generateCSRWithBiometrics(
    activity: FragmentActivity,
    enclave: EnclaveManager,
    userData: UserData,
    onSuccess: (String) -> Unit,
    onError: (String) -> Unit
) {
    val TAG = "generateCSRWithBiometrics"
    
    Log.d(TAG, "Starting CSR generation with biometric authentication")
    
    // Create BiometricPrompt callback
    val biometricPrompt = BiometricPrompt(
        activity,
        ContextCompat.getMainExecutor(activity),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d(TAG, "Biometric authentication succeeded")
                
                try {
                    // Generate CSR
                    val csrEngine = CSRManager(
                        tag = EnclaveManager.ALIAS_LOCAL_DEVICE,
                        commonName = userData.commonName,
                        organization = "Signosoft",
                        organizational_unit = "eWallet",
                        locality = userData.locality,
                        state = userData.locality,
                        country = userData.country,
                        email = userData.email,
                        enclave = enclave
                    )
                    
                    val pemString = csrEngine.buildPEM()
                    
                    if (pemString != null) {
                        Log.d(TAG, "Successfully generated CSR for: ${userData.commonName}")
                        onSuccess(pemString)
                    } else {
                        Log.e(TAG, "CSR generation returned null")
                        onError("Failed to generate CSR")
                    }
                    
                } catch (e: Exception) {
                    Log.e(TAG, "Error during CSR generation: ${e.message}")
                    onError(e.message ?: "Unknown error")
                }
            }
            
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.e(TAG, "Biometric authentication error: $errString")
                onError("Authentication error: $errString")
            }
            
            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.w(TAG, "Biometric authentication failed")
            }
        }
    )
    
    // Build prompt info
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Generate CSR")
        .setSubtitle("Authenticate to create certificate signing request for ${userData.commonName}")
        .setAllowedAuthenticators(
            androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
            androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
        .build()
    
    // Show biometric prompt
    biometricPrompt.authenticate(promptInfo)
}
