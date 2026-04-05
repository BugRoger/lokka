import { ClientSecretCredential, ClientCertificateCredential, InteractiveBrowserCredential, DeviceCodeCredential } from "@azure/identity";
import jwt from "jsonwebtoken";
import { logger } from "./logger.js";
import { LokkaClientId, LokkaDefaultTenantId, LokkaDefaultRedirectUri, LokkaTokenPath } from "./constants.js";
import { createServer } from "http";
import { randomBytes, createHash } from "crypto";
import { exec } from "child_process";
import fs from "fs";
import path from "path";
// Constants
const ONE_HOUR_IN_MS = 60 * 60 * 1000; // One hour in milliseconds
// Helper function to parse JWT and extract scopes
function parseJwtScopes(token) {
    try {
        // Decode JWT without verifying signature (we trust the token from Azure Identity)
        const decoded = jwt.decode(token);
        if (!decoded || typeof decoded !== 'object') {
            logger.info("Failed to decode JWT token");
            return [];
        }
        // Extract scopes from the 'scp' claim (space-separated string)
        const scopesString = decoded.scp;
        if (typeof scopesString === 'string') {
            return scopesString.split(' ').filter(scope => scope.length > 0);
        }
        // Some tokens might have roles instead of scopes
        const roles = decoded.roles;
        if (Array.isArray(roles)) {
            return roles;
        }
        logger.info("No scopes found in JWT token");
        return [];
    }
    catch (error) {
        logger.error("Error parsing JWT token for scopes", error);
        return [];
    }
}
// Simple authentication provider that works with Azure Identity TokenCredential
export class TokenCredentialAuthProvider {
    credential;
    constructor(credential) {
        this.credential = credential;
    }
    async getAccessToken() {
        const token = await this.credential.getToken("https://graph.microsoft.com/.default");
        if (!token) {
            throw new Error("Failed to acquire access token");
        }
        return token.token;
    }
}
export class ClientProvidedTokenCredential {
    accessToken;
    expiresOn;
    constructor(accessToken, expiresOn) {
        if (accessToken) {
            this.accessToken = accessToken;
            this.expiresOn = expiresOn || new Date(Date.now() + ONE_HOUR_IN_MS); // Default 1 hour
        }
        else {
            this.expiresOn = new Date(0); // Set to epoch to indicate no valid token
        }
    }
    async getToken(scopes) {
        if (!this.accessToken || !this.expiresOn || this.expiresOn <= new Date()) {
            logger.error("Access token is not available or has expired");
            return null;
        }
        return {
            token: this.accessToken,
            expiresOnTimestamp: this.expiresOn.getTime()
        };
    }
    updateToken(accessToken, expiresOn) {
        this.accessToken = accessToken;
        this.expiresOn = expiresOn || new Date(Date.now() + ONE_HOUR_IN_MS);
        logger.info("Access token updated successfully");
    }
    isExpired() {
        return !this.expiresOn || this.expiresOn <= new Date();
    }
    getExpirationTime() {
        return this.expiresOn || new Date(0);
    }
    // Getter for access token (for internal use by AuthManager)
    getAccessToken() {
        return this.accessToken;
    }
}
export var AuthMode;
(function (AuthMode) {
    AuthMode["ClientCredentials"] = "client_credentials";
    AuthMode["ClientProvidedToken"] = "client_provided_token";
    AuthMode["Interactive"] = "interactive";
    AuthMode["Certificate"] = "certificate";
    AuthMode["PersistentToken"] = "persistent_token";
})(AuthMode || (AuthMode = {}));
const TOKEN_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const AUTHORIZE_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const REFRESH_BUFFER_SECONDS = 300; // refresh 5 minutes before expiry
// Default scopes for interactive auth — offline_access is required for refresh tokens
const DEFAULT_INTERACTIVE_SCOPES = [
    "User.Read",
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "Calendars.Read",
    "Calendars.ReadWrite",
    "Tasks.Read",
    "Files.Read",
    "Contacts.Read",
    "offline_access",
    "OnlineMeetingArtifact.Read.All",
    "OnlineMeetings.Read",
    "OnlineMeetings.ReadWrite"
];
/**
 * TokenCredential that persists tokens to disk and refreshes via HTTP.
 * First call with no token file triggers interactive OAuth2 auth code flow with PKCE.
 * Subsequent calls refresh silently via refresh_token grant.
 */
export class PersistentTokenCredential {
    clientId;
    redirectPort;
    cachedToken = null;
    constructor(clientId = LokkaClientId, redirectPort = 0) {
        this.clientId = clientId;
        this.redirectPort = redirectPort;
    }
    async getToken(scopes) {
        // Try loading cached token
        if (!this.cachedToken) {
            this.cachedToken = this._loadTokenFile();
        }
        if (this.cachedToken) {
            const now = Math.floor(Date.now() / 1000);
            if (this.cachedToken.expires_at > now + REFRESH_BUFFER_SECONDS) {
                // Token still valid
                return {
                    token: this.cachedToken.access_token,
                    expiresOnTimestamp: this.cachedToken.expires_at * 1000,
                };
            }
            // Token expired or expiring soon — refresh it
            logger.info("Access token expired or expiring soon, refreshing...");
            const refreshed = await this._refreshToken();
            if (refreshed) {
                return {
                    token: refreshed.access_token,
                    expiresOnTimestamp: refreshed.expires_at * 1000,
                };
            }
            // Refresh failed — fall through to interactive auth
            logger.info("Token refresh failed, falling back to interactive auth");
        }
        // No token file or refresh failed — do interactive auth
        logger.info("No cached token found, starting interactive authentication...");
        const token = await this._interactiveAuth();
        return {
            token: token.access_token,
            expiresOnTimestamp: token.expires_at * 1000,
        };
    }
    _loadTokenFile() {
        try {
            if (!fs.existsSync(LokkaTokenPath)) {
                return null;
            }
            const data = fs.readFileSync(LokkaTokenPath, "utf-8");
            const parsed = JSON.parse(data);
            if (!parsed.access_token || !parsed.refresh_token) {
                logger.info("Token file missing required fields");
                return null;
            }
            return parsed;
        }
        catch (error) {
            logger.error("Failed to load token file", error);
            return null;
        }
    }
    _saveTokenFile(data) {
        const dir = path.dirname(LokkaTokenPath);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(LokkaTokenPath, JSON.stringify(data, null, 2), { mode: 0o600 });
        logger.info("Token saved to disk");
    }
    async _refreshToken() {
        if (!this.cachedToken?.refresh_token) {
            return null;
        }
        const body = new URLSearchParams({
            client_id: this.cachedToken.client_id || this.clientId,
            grant_type: "refresh_token",
            refresh_token: this.cachedToken.refresh_token,
            scope: this.cachedToken.scope || DEFAULT_INTERACTIVE_SCOPES.join(" "),
        });
        try {
            const response = await fetch(TOKEN_ENDPOINT, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: body.toString(),
            });
            if (!response.ok) {
                const errorText = await response.text();
                logger.error(`Token refresh failed: ${response.status} - ${errorText}`);
                return null;
            }
            const result = await response.json();
            if (!result.access_token) {
                logger.error("Token refresh response missing access_token");
                return null;
            }
            const tokenData = {
                access_token: result.access_token,
                refresh_token: result.refresh_token || this.cachedToken.refresh_token,
                expires_at: Math.floor(Date.now() / 1000) + (result.expires_in || 3600),
                scope: result.scope || this.cachedToken.scope,
                client_id: this.cachedToken.client_id || this.clientId,
            };
            this._saveTokenFile(tokenData);
            this.cachedToken = tokenData;
            logger.info("Token refreshed successfully");
            return tokenData;
        }
        catch (error) {
            logger.error("Token refresh error", error);
            return null;
        }
    }
    async _interactiveAuth() {
        // Generate PKCE challenge
        const codeVerifier = randomBytes(32).toString("base64url");
        const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
        const scopes = DEFAULT_INTERACTIVE_SCOPES.join(" ");
        // Start local server to capture the redirect
        return new Promise((resolve, reject) => {
            const server = createServer(async (req, res) => {
                try {
                    const url = new URL(req.url || "/", `http://localhost`);
                    const code = url.searchParams.get("code");
                    const error = url.searchParams.get("error");
                    if (error) {
                        const errorDesc = url.searchParams.get("error_description") || error;
                        res.writeHead(400, { "Content-Type": "text/html" });
                        res.end(`<html><body><h2>Authentication Failed</h2><p>${errorDesc}</p></body></html>`);
                        server.close();
                        reject(new Error(`Authentication failed: ${errorDesc}`));
                        return;
                    }
                    if (!code) {
                        // Not the redirect callback — ignore (could be favicon.ico etc.)
                        res.writeHead(404);
                        res.end();
                        return;
                    }
                    // Exchange code for tokens
                    const address = server.address();
                    const port = typeof address === "object" && address ? address.port : this.redirectPort;
                    const redirectUri = `http://localhost:${port}`;
                    const body = new URLSearchParams({
                        client_id: this.clientId,
                        grant_type: "authorization_code",
                        code: code,
                        redirect_uri: redirectUri,
                        code_verifier: codeVerifier,
                    });
                    const tokenResponse = await fetch(TOKEN_ENDPOINT, {
                        method: "POST",
                        headers: { "Content-Type": "application/x-www-form-urlencoded" },
                        body: body.toString(),
                    });
                    if (!tokenResponse.ok) {
                        const errorText = await tokenResponse.text();
                        res.writeHead(500, { "Content-Type": "text/html" });
                        res.end(`<html><body><h2>Token Exchange Failed</h2><pre>${errorText}</pre></body></html>`);
                        server.close();
                        reject(new Error(`Token exchange failed: ${errorText}`));
                        return;
                    }
                    const result = await tokenResponse.json();
                    const tokenData = {
                        access_token: result.access_token,
                        refresh_token: result.refresh_token,
                        expires_at: Math.floor(Date.now() / 1000) + (result.expires_in || 3600),
                        scope: result.scope || scopes,
                        client_id: this.clientId,
                    };
                    this._saveTokenFile(tokenData);
                    this.cachedToken = tokenData;
                    res.writeHead(200, { "Content-Type": "text/html" });
                    res.end(`<html><body><h2>Authentication Successful</h2><p>You can close this window.</p></body></html>`);
                    server.close();
                    resolve(tokenData);
                }
                catch (err) {
                    res.writeHead(500, { "Content-Type": "text/html" });
                    res.end(`<html><body><h2>Error</h2><pre>${err}</pre></body></html>`);
                    server.close();
                    reject(err);
                }
            });
            server.listen(this.redirectPort, "127.0.0.1", async () => {
                const address = server.address();
                const port = typeof address === "object" && address ? address.port : this.redirectPort;
                const redirectUri = `http://localhost:${port}`;
                const authUrl = new URL(AUTHORIZE_ENDPOINT);
                authUrl.searchParams.set("client_id", this.clientId);
                authUrl.searchParams.set("response_type", "code");
                authUrl.searchParams.set("redirect_uri", redirectUri);
                authUrl.searchParams.set("scope", scopes);
                authUrl.searchParams.set("code_challenge", codeChallenge);
                authUrl.searchParams.set("code_challenge_method", "S256");
                authUrl.searchParams.set("response_mode", "query");
                const authUrlStr = authUrl.toString();
                logger.info(`Opening browser for authentication: ${authUrlStr}`);
                console.error(`\n🔐 Opening browser for authentication...`);
                console.error(`If the browser doesn't open, visit: ${authUrlStr}\n`);
                // Open browser using platform-native command
                const platform = process.platform;
                const cmd = platform === "darwin" ? "open" : platform === "win32" ? "start" : "xdg-open";
                exec(`${cmd} "${authUrlStr}"`, (err) => {
                    if (err) {
                        console.error(`⚠️  Could not open browser automatically. Please open this URL manually:\n${authUrlStr}`);
                    }
                });
            });
            // Timeout after 2 minutes
            setTimeout(() => {
                server.close();
                reject(new Error("Authentication timed out after 2 minutes"));
            }, 120_000);
        });
    }
}
export class AuthManager {
    credential = null;
    config;
    constructor(config) {
        this.config = config;
    }
    async initialize() {
        switch (this.config.mode) {
            case AuthMode.ClientCredentials:
                if (!this.config.tenantId || !this.config.clientId || !this.config.clientSecret) {
                    throw new Error("Client credentials mode requires tenantId, clientId, and clientSecret");
                }
                logger.info("Initializing Client Credentials authentication");
                this.credential = new ClientSecretCredential(this.config.tenantId, this.config.clientId, this.config.clientSecret);
                break;
            case AuthMode.ClientProvidedToken:
                logger.info("Initializing Client Provided Token authentication");
                this.credential = new ClientProvidedTokenCredential(this.config.accessToken, this.config.expiresOn);
                break;
            case AuthMode.Certificate:
                if (!this.config.tenantId || !this.config.clientId || !this.config.certificatePath) {
                    throw new Error("Certificate mode requires tenantId, clientId, and certificatePath");
                }
                logger.info("Initializing Certificate authentication");
                this.credential = new ClientCertificateCredential(this.config.tenantId, this.config.clientId, {
                    certificatePath: this.config.certificatePath,
                    certificatePassword: this.config.certificatePassword
                });
                break;
            case AuthMode.Interactive:
                // Use defaults if not provided
                const tenantId = this.config.tenantId || LokkaDefaultTenantId;
                const clientId = this.config.clientId || LokkaClientId;
                logger.info(`Initializing Interactive authentication with tenant ID: ${tenantId}, client ID: ${clientId}`);
                try {
                    // Try Interactive Browser first
                    this.credential = new InteractiveBrowserCredential({
                        tenantId: tenantId,
                        clientId: clientId,
                        redirectUri: this.config.redirectUri || LokkaDefaultRedirectUri,
                    });
                }
                catch (error) {
                    // Fallback to Device Code flow
                    logger.info("Interactive browser failed, falling back to device code flow");
                    this.credential = new DeviceCodeCredential({
                        tenantId: tenantId,
                        clientId: clientId,
                        userPromptCallback: (info) => {
                            console.log(`\n🔐 Authentication Required:`);
                            console.log(`Please visit: ${info.verificationUri}`);
                            console.log(`And enter code: ${info.userCode}\n`);
                            return Promise.resolve();
                        },
                    });
                }
                break;
            case AuthMode.PersistentToken:
                logger.info("Initializing Persistent Token authentication (cached token with silent refresh)");
                this.credential = new PersistentTokenCredential(this.config.clientId || LokkaClientId);
                break;
            default:
                throw new Error(`Unsupported authentication mode: ${this.config.mode}`);
        }
        // Test the credential
        await this.testCredential();
    }
    updateAccessToken(accessToken, expiresOn) {
        if (this.config.mode === AuthMode.ClientProvidedToken && this.credential instanceof ClientProvidedTokenCredential) {
            this.credential.updateToken(accessToken, expiresOn);
        }
        else {
            throw new Error("Token update only supported in client provided token mode");
        }
    }
    async testCredential() {
        if (!this.credential) {
            throw new Error("Credential not initialized");
        }
        // Skip testing if ClientProvidedToken mode has no initial token
        if (this.config.mode === AuthMode.ClientProvidedToken && !this.config.accessToken) {
            logger.info("Skipping initial credential test as no token was provided at startup.");
            return;
        }
        try {
            const token = await this.credential.getToken("https://graph.microsoft.com/.default");
            if (!token) {
                throw new Error("Failed to acquire token");
            }
            logger.info("Authentication successful");
        }
        catch (error) {
            logger.error("Authentication test failed", error);
            throw error;
        }
    }
    getGraphAuthProvider() {
        if (!this.credential) {
            throw new Error("Authentication not initialized");
        }
        return new TokenCredentialAuthProvider(this.credential);
    }
    getAzureCredential() {
        if (!this.credential) {
            throw new Error("Authentication not initialized");
        }
        return this.credential;
    }
    getAuthMode() {
        return this.config.mode;
    }
    isClientCredentials() {
        return this.config.mode === AuthMode.ClientCredentials;
    }
    isClientProvidedToken() {
        return this.config.mode === AuthMode.ClientProvidedToken;
    }
    isInteractive() {
        return this.config.mode === AuthMode.Interactive;
    }
    isPersistentToken() {
        return this.config.mode === AuthMode.PersistentToken;
    }
    async getTokenStatus() {
        if (this.credential instanceof ClientProvidedTokenCredential) {
            const tokenStatus = {
                isExpired: this.credential.isExpired(),
                expiresOn: this.credential.getExpirationTime()
            };
            // If we have a valid token, parse it to extract scopes
            if (!tokenStatus.isExpired) {
                const accessToken = this.credential.getAccessToken();
                if (accessToken) {
                    try {
                        const scopes = parseJwtScopes(accessToken);
                        return {
                            ...tokenStatus,
                            scopes: scopes
                        };
                    }
                    catch (error) {
                        logger.error("Error parsing token scopes in getTokenStatus", error);
                        return tokenStatus;
                    }
                }
            }
            return tokenStatus;
        }
        else if (this.credential) {
            // For other credential types, try to get a fresh token and parse it
            try {
                const accessToken = await this.credential.getToken("https://graph.microsoft.com/.default");
                if (accessToken && accessToken.token) {
                    const scopes = parseJwtScopes(accessToken.token);
                    return {
                        isExpired: false,
                        expiresOn: new Date(accessToken.expiresOnTimestamp),
                        scopes: scopes
                    };
                }
            }
            catch (error) {
                logger.error("Error getting token for scope parsing", error);
            }
        }
        return { isExpired: false };
    }
}
