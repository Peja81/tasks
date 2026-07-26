package org.tasks.gtasks

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import org.tasks.R
import org.tasks.analytics.Constants
import org.tasks.analytics.Firebase
import org.tasks.auth.OAuthConfig
import org.tasks.auth.OAuthResult
import org.tasks.auth.PKCE
import org.tasks.auth.TasksOAuthClient
import org.tasks.data.dao.CaldavDao
import org.tasks.data.entity.CaldavAccount
import org.tasks.extensions.htmlEscape
import org.tasks.googleapis.GoogleTasksTokenData
import org.tasks.security.KeyStoreEncryption
import org.tasks.time.DateTimeUtils2.currentTimeMillis
import timber.log.Timber
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.net.URLDecoder
import javax.inject.Inject
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private const val GOOGLE_TASKS_SCOPE = "https://www.googleapis.com/auth/tasks"
private const val GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
private const val GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

/**
 * Talks directly to Google using a self-registered OAuth client (Google Cloud Console,
 * "Desktop app" credential type) — no third-party proxy involved. The client ID/secret
 * come from `google_tasks_client_id`/`google_tasks_client_secret` (see app/build.gradle.kts).
 */
@HiltViewModel
class GoogleTasksSignInViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val caldavDao: CaldavDao,
    private val encryption: KeyStoreEncryption,
    private val firebase: Firebase,
) : ViewModel() {
    private val oauthClient = TasksOAuthClient()
    private var started = false

    var error by mutableStateOf<String?>(null)
        private set
    var complete by mutableStateOf(false)
        private set

    fun start(openUrl: (String) -> Unit) {
        if (started) {
            return
        }
        started = true
        viewModelScope.launch(Dispatchers.IO) {
            try {
                signIn(openUrl)
                complete = true
            } catch (e: Exception) {
                Timber.e(e)
                error = e.message ?: e.javaClass.simpleName
            }
        }
    }

    private suspend fun signIn(openUrl: (String) -> Unit) {
        val clientId = context.getString(R.string.google_tasks_client_id)
        val clientSecret = context.getString(R.string.google_tasks_client_secret)
        if (clientId.isBlank() || clientSecret.isBlank()) {
            throw Exception(context.getString(R.string.google_tasks_not_configured))
        }

        val codeVerifier = PKCE.generateVerifier()
        val codeChallenge = PKCE.generateChallenge(codeVerifier)
        val state = PKCE.generateVerifier()

        val (config, code) = listenForCallback(state) { port ->
            val redirectUri = "http://127.0.0.1:$port"
            val authConfig = OAuthConfig(
                authorizationEndpoint = GOOGLE_AUTH_ENDPOINT,
                tokenEndpoint = GOOGLE_TOKEN_ENDPOINT,
                clientId = clientId,
                redirectUri = redirectUri,
                scope = "$GOOGLE_TASKS_SCOPE openid email",
                state = state,
            )
            val authUrl = oauthClient.buildAuthUrl(
                authConfig,
                codeChallenge,
                state,
                mapOf("access_type" to "offline", "prompt" to "consent"),
            )
            Timber.d("Opening browser: $authUrl")
            openUrl(authUrl)
            authConfig
        }

        Timber.d("Got authorization code, exchanging...")
        val result = oauthClient.exchangeCode(config, code, codeVerifier, clientSecret = clientSecret)
        setupAccount(result)
        firebase.logEvent(
            R.string.event_sync_add_account,
            R.string.param_type to Constants.SYNC_TYPE_GOOGLE_TASKS,
        )
    }

    private suspend fun setupAccount(result: OAuthResult) {
        val email = result.idToken?.email
            ?: throw Exception("No email in Google Tasks sign-in response")
        val refreshToken = result.refreshToken
            ?: throw Exception(
                "No refresh token returned—remove app access at " +
                        "myaccount.google.com/permissions and try signing in again"
            )
        val grantedScopes = result.grantedScopes
        if (grantedScopes != null && GOOGLE_TASKS_SCOPE !in grantedScopes) {
            throw Exception(context.getString(R.string.google_tasks_permission_not_granted))
        }

        val tokenData = GoogleTasksTokenData(
            accessToken = result.accessToken,
            refreshToken = refreshToken,
            tokenEndpoint = result.tokenEndpoint ?: GOOGLE_TOKEN_ENDPOINT,
            clientId = result.clientId
                ?: throw Exception("No client_id in OAuth result"),
            expiresAt = result.expiresIn
                ?.let { currentTimeMillis() + it * 1000 }
                ?: 0,
        )
        val encrypted = encryption.encrypt(tokenData.serialize())

        val existing = caldavDao.getAccount(CaldavAccount.TYPE_GOOGLE_TASKS, email)
        if (existing != null) {
            caldavDao.update(existing.copy(password = encrypted, error = ""))
        } else {
            caldavDao.insert(
                CaldavAccount(
                    accountType = CaldavAccount.TYPE_GOOGLE_TASKS,
                    uuid = email,
                    name = email,
                    username = email,
                    password = encrypted,
                )
            )
        }
    }

    private suspend fun listenForCallback(
        expectedState: String,
        onReady: (port: Int) -> OAuthConfig,
    ): Pair<OAuthConfig, String> = suspendCancellableCoroutine { cont ->
        val serverSocket = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        serverSocket.soTimeout = 300_000 // 5 minute timeout
        val port = serverSocket.localPort

        cont.invokeOnCancellation {
            serverSocket.close()
        }

        Timber.d("Listening on port $port")
        val config = onReady(port)

        val socket = serverSocket.accept()
        try {
            val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
            val requestLine = reader.readLine() ?: ""
            val path = requestLine.split(" ").getOrElse(1) { "" }
            val query = path.substringAfter("?", "")
            val params = query.split("&")
                .filter { it.contains("=") }
                .associate {
                    val (key, value) = it.split("=", limit = 2)
                    key to URLDecoder.decode(value, "UTF-8")
                }

            val code = params["code"]
            val callbackError = params["error"]
            val returnedState = params["state"]

            val responseBody = if (code != null) {
                "<html><body>" +
                        "<h2>Sign in successful!</h2>" +
                        "<p>You can close this window and return to Tasks.</p>" +
                        "<script>window.close()</script>" +
                        "</body></html>"
            } else {
                "<html><body>" +
                        "<h2>Sign in failed</h2>" +
                        "<p>${(callbackError ?: "Unknown error").htmlEscape()}</p>" +
                        "</body></html>"
            }

            val response = "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: text/html\r\n" +
                    "Content-Length: ${responseBody.toByteArray().size}\r\n" +
                    "Connection: close\r\n" +
                    "\r\n" +
                    responseBody
            socket.getOutputStream().write(response.toByteArray())
            socket.getOutputStream().flush()

            if (code != null) {
                if (returnedState != expectedState) {
                    cont.resumeWithException(Exception("OAuth state mismatch"))
                } else {
                    cont.resume(config to code)
                }
            } else {
                cont.resumeWithException(Exception(callbackError ?: "Authorization failed"))
            }
        } finally {
            socket.close()
            serverSocket.close()
        }
    }
}
