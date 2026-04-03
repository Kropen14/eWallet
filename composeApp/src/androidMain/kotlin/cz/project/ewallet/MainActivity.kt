package cz.project.ewallet

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.flow.MutableStateFlow

val bankIdTokenFlow = MutableStateFlow<String?>(null)

class MainActivity : FragmentActivity() {
        override fun onCreate(savedInstanceState: Bundle?) {
                enableEdgeToEdge()
                super.onCreate(savedInstanceState)

                handleIntent(intent)

                setContent { App() }
        }

        override fun onNewIntent(intent: Intent) {
                super.onNewIntent(intent)
                handleIntent(intent)
        }

        private fun handleIntent(intent: Intent?) {
                val uri = intent?.data
                if (uri != null && uri.scheme == "ewallet" && uri.host == "auth") {
                        val token = uri.getQueryParameter("token")
                        if (token != null) {
                                Log.d("MainActivity", "BankiD token caught!")
                                bankIdTokenFlow.value = token
                        }
                }
        }
}

@Preview
@Composable
fun AppAndroidPreview() {
        App()
}
