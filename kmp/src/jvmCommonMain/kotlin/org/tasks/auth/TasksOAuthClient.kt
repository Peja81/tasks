package org.tasks.auth

import co.touchlab.kermit.Logger
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Dns
import okhttp3.FormBody
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.dnsoverhttps.DnsOverHttps
import java.net.InetAddress
import java.net.URLEncoder
import java.net.UnknownHostException

/**
 * Some Android devices/carriers fail to resolve googleapis.com via the system DNS resolver
 * (a known Android bug), even though the browser resolves it fine using its own DNS.
 * Falls back to DNS-over-HTTPS (the same approach browsers use) when the system resolver fails.
 */
private class FallbackDns(
    private val primary: Dns,
    private val fallback: Dns,
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> = try {
        primary.lookup(hostname)
    } catch (e: UnknownHostException) {
        Logger.w("TasksOAuthClient") { "System DNS failed for $hostname, falling back to DNS-over-HTTPS" }
        fallback.lookup(hostname)
    }
}

data class OAuthConfig(
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val clientId: String,
    val redirectUri: String,
    val scope: String,
    val state: String = "",
)

data class OAuthResult(
    val accessToken: String,
    val idToken: IdToken? = null,
    val refreshToken: String? = null,
    val tokenEndpoint: String? = null,
    val clientId: String? = null,
    val expiresIn: Long? = null,
    val grantedScopes: String? = null,
)

class TasksOAuthClient(
    private val httpClient: OkHttpClient = sharedHttpClient,
) {
    companion object {
        private val sharedHttpClient: OkHttpClient by lazy {
            val bootstrapClient = OkHttpClient.Builder()
                .connectTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
                .build()
            val dnsOverHttps = DnsOverHttps.Builder()
                .client(bootstrapClient)
                .url("https://dns.google/dns-query".toHttpUrl())
                .bootstrapDnsHosts(
                    InetAddress.getByName("8.8.8.8"),
                    InetAddress.getByName("8.8.4.4"),
                )
                .build()
            bootstrapClient.newBuilder()
                .dns(FallbackDns(Dns.SYSTEM, dnsOverHttps))
                .build()
        }
    }
    fun fetchDiscovery(discoveryUrl: String, authHeader: String? = null): JsonObject {
        val request = Request.Builder()
            .url(discoveryUrl)
            .apply { authHeader?.let { header("Authorization", it) } }
            .build()
        Logger.d("TasksOAuthClient") { "Fetching: $discoveryUrl" }
        val response = httpClient.newCall(request).execute()
        val body = response.body?.string() ?: throw Exception("Empty discovery response")
        Logger.d("TasksOAuthClient") { "Discovery response: ${response.code}" }
        if (!response.isSuccessful) {
            throw Exception("Discovery request failed: ${response.code} $body")
        }
        return Json.parseToJsonElement(body) as JsonObject
    }

    fun buildAuthUrl(
        config: OAuthConfig,
        codeChallenge: String,
        state: String,
        extraParams: Map<String, String> = emptyMap(),
    ): String {
        fun encode(value: String) = URLEncoder.encode(value, "UTF-8")
        val base = "${config.authorizationEndpoint}?" +
            "client_id=${encode(config.clientId)}" +
            "&redirect_uri=${encode(config.redirectUri)}" +
            "&response_type=code" +
            "&scope=${encode(config.scope)}" +
            "&code_challenge=${encode(codeChallenge)}" +
            "&code_challenge_method=S256" +
            "&state=${encode(state)}"
        val extra = extraParams.entries.joinToString("") { (k, v) ->
            "&${encode(k)}=${encode(v)}"
        }
        return base + extra
    }

    fun exchangeCode(
        config: OAuthConfig,
        code: String,
        codeVerifier: String,
        authHeader: String? = null,
        clientSecret: String? = null,
    ): OAuthResult {
        val formBody = FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("client_id", config.clientId)
            .add("redirect_uri", config.redirectUri)
            .add("code", code)
            .add("code_verifier", codeVerifier)
            .apply { clientSecret?.let { add("client_secret", it) } }
            .build()

        val request = Request.Builder()
            .url(config.tokenEndpoint)
            .post(formBody)
            .header("Accept", "application/json")
            .apply { authHeader?.let { header("Authorization", it) } }
            .build()

        val response = httpClient.newCall(request).execute()
        val body = response.body?.string() ?: throw Exception("Empty token response")

        if (!response.isSuccessful) {
            Logger.e("TasksOAuthClient") { "Token exchange failed: ${response.code} $body" }
            throw Exception("Token exchange failed: ${response.code}")
        }

        val json = Json.parseToJsonElement(body) as JsonObject
        val accessToken = json["access_token"]?.jsonPrimitive?.content
            ?: throw Exception("No access_token in response")
        val idTokenStr = json["id_token"]?.jsonPrimitive?.content
        val refreshToken = json["refresh_token"]?.jsonPrimitive?.content
        val expiresIn = json["expires_in"]?.jsonPrimitive?.content?.toLongOrNull()
        val grantedScopes = json["scope"]?.jsonPrimitive?.content
        Logger.d("TasksOAuthClient") { "Token exchange granted scopes: $grantedScopes" }

        return OAuthResult(
            accessToken = accessToken,
            idToken = idTokenStr?.let { IdToken(it) },
            refreshToken = refreshToken,
            tokenEndpoint = config.tokenEndpoint,
            clientId = config.clientId,
            expiresIn = expiresIn,
            grantedScopes = grantedScopes,
        )
    }

    data class RefreshResult(
        val accessToken: String,
        val expiresIn: Long?,
    )

    fun refreshToken(
        tokenEndpoint: String,
        clientId: String,
        refreshToken: String,
        authHeader: String? = null,
        clientSecret: String? = null,
    ): RefreshResult {
        val formBody = FormBody.Builder()
            .add("grant_type", "refresh_token")
            .add("client_id", clientId)
            .add("refresh_token", refreshToken)
            .apply { clientSecret?.let { add("client_secret", it) } }
            .build()

        val request = Request.Builder()
            .url(tokenEndpoint)
            .post(formBody)
            .header("Accept", "application/json")
            .apply { authHeader?.let { header("Authorization", it) } }
            .build()

        val response = httpClient.newCall(request).execute()
        val body = response.body?.string() ?: throw Exception("Empty refresh response")

        if (!response.isSuccessful) {
            Logger.e("TasksOAuthClient") { "Token refresh failed: ${response.code} $body" }
            throw Exception("Token refresh failed: ${response.code}")
        }

        val json = Json.parseToJsonElement(body) as JsonObject
        val accessToken = json["access_token"]?.jsonPrimitive?.content
            ?: throw Exception("No access_token in refresh response")
        val expiresIn = json["expires_in"]?.jsonPrimitive?.content?.toLongOrNull()
        return RefreshResult(accessToken = accessToken, expiresIn = expiresIn)
    }
}
