import * as crypto from "crypto"
import * as http from "http"
import * as https from "https"
import { URL } from "url"
import { z } from "zod"
import { StateManager } from "@/core/storage/StateManager"
import { Logger } from "@/shared/services/Logger"

/**
 * Claude OAuth Configuration
 *
 * Uses Anthropic's OAuth 2.0 + PKCE flow for claude.ai subscribers.
 * Client ID matches the one used by the official Claude Code CLI.
 */
export const CLAUDE_OAUTH_CONFIG = {
	authorizationEndpoint: "https://claude.ai/oauth/authorize",
	tokenEndpoint: "https://platform.claude.com/v1/oauth/token",
	clientId: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
	redirectUri: "http://localhost:54545/callback",
	scopes: "user:inference",
	callbackPort: 54545,
} as const

const CLAUDE_OAUTH_CREDENTIALS_KEY = "claude-oauth-credentials"

const claudeOAuthCredentialsSchema = z.object({
	type: z.literal("claude-oauth"),
	access_token: z.string().min(1),
	refresh_token: z.string().min(1).optional(),
	expires: z.number(),
	email: z.string().optional(),
})

export type ClaudeOAuthCredentials = z.infer<typeof claudeOAuthCredentialsSchema>

const tokenResponseSchema = z.object({
	access_token: z.string(),
	refresh_token: z.string().optional(),
	expires_in: z.number(),
	token_type: z.string().optional(),
})

const userInfoSchema = z.object({
	email: z.string().optional(),
	name: z.string().optional(),
})

export function generateCodeVerifier(): string {
	return crypto.randomBytes(32).toString("base64url")
}

export function generateCodeChallenge(verifier: string): string {
	return crypto.createHash("sha256").update(verifier).digest().toString("base64url")
}

export function generateState(): string {
	return crypto.randomBytes(16).toString("hex")
}

export function buildAuthorizationUrl(codeChallenge: string, state: string): string {
	const params = new URLSearchParams({
		client_id: CLAUDE_OAUTH_CONFIG.clientId,
		redirect_uri: CLAUDE_OAUTH_CONFIG.redirectUri,
		scope: CLAUDE_OAUTH_CONFIG.scopes,
		code_challenge: codeChallenge,
		code_challenge_method: "S256",
		response_type: "code",
		state,
	})
	return `${CLAUDE_OAUTH_CONFIG.authorizationEndpoint}?${params.toString()}`
}

function httpsPost(url: string, body: Record<string, string>): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const payload = new URLSearchParams(body).toString()
		const parsed = new URL(url)
		const req = https.request(
			{
				hostname: parsed.hostname,
				path: parsed.pathname + parsed.search,
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					"Content-Length": Buffer.byteLength(payload),
				},
			},
			(res) => {
				let data = ""
				res.on("data", (chunk) => (data += chunk))
				res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }))
			},
		)
		req.on("error", reject)
		req.setTimeout(30000, () => {
			req.destroy(new Error("Token request timed out"))
		})
		req.write(payload)
		req.end()
	})
}

async function exchangeCodeForTokens(code: string, codeVerifier: string, state: string): Promise<ClaudeOAuthCredentials> {
	const result = await httpsPost(CLAUDE_OAUTH_CONFIG.tokenEndpoint, {
		grant_type: "authorization_code",
		client_id: CLAUDE_OAUTH_CONFIG.clientId,
		code,
		redirect_uri: CLAUDE_OAUTH_CONFIG.redirectUri,
		code_verifier: codeVerifier,
		state,
	})

	if (result.status < 200 || result.status >= 300) {
		throw new Error(`Token exchange failed: ${result.status} - ${result.body}`)
	}

	const data = JSON.parse(result.body)
	const tokenResponse = tokenResponseSchema.parse(data)

	const expiresAt = Date.now() + tokenResponse.expires_in * 1000

	// Attempt to fetch user email from Anthropic API
	let email: string | undefined
	try {
		const meResult = await new Promise<{ status: number; body: string }>((resolve, reject) => {
			const req = https.request(
				{
					hostname: "api.anthropic.com",
					path: "/v1/me",
					method: "GET",
					headers: {
						Authorization: `Bearer ${tokenResponse.access_token}`,
						"anthropic-version": "2023-06-01",
					},
				},
				(res) => {
					let data = ""
					res.on("data", (chunk) => (data += chunk))
					res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }))
				},
			)
			req.on("error", reject)
			req.setTimeout(10000, () => req.destroy(new Error("User info request timed out")))
			req.end()
		})
		if (meResult.status >= 200 && meResult.status < 300) {
			const parsed = userInfoSchema.safeParse(JSON.parse(meResult.body))
			if (parsed.success) {
				email = parsed.data.email
			}
		}
	} catch (error) {
		Logger.error("[claude-oauth] Failed to fetch user info:", error)
	}

	return {
		type: "claude-oauth",
		access_token: tokenResponse.access_token,
		refresh_token: tokenResponse.refresh_token,
		expires: expiresAt,
		email,
	}
}

async function refreshAccessToken(credentials: ClaudeOAuthCredentials): Promise<ClaudeOAuthCredentials> {
	if (!credentials.refresh_token) {
		throw new Error("No refresh token available")
	}

	const result = await httpsPost(CLAUDE_OAUTH_CONFIG.tokenEndpoint, {
		grant_type: "refresh_token",
		client_id: CLAUDE_OAUTH_CONFIG.clientId,
		refresh_token: credentials.refresh_token,
	})

	if (result.status < 200 || result.status >= 300) {
		throw new Error(`Token refresh failed: ${result.status} - ${result.body}`)
	}

	const data = JSON.parse(result.body)
	const tokenResponse = tokenResponseSchema.parse(data)
	const expiresAt = Date.now() + tokenResponse.expires_in * 1000

	return {
		type: "claude-oauth",
		access_token: tokenResponse.access_token,
		refresh_token: tokenResponse.refresh_token ?? credentials.refresh_token,
		expires: expiresAt,
		email: credentials.email,
	}
}

function isTokenExpired(credentials: ClaudeOAuthCredentials): boolean {
	const bufferMs = 5 * 60 * 1000
	return Date.now() >= credentials.expires - bufferMs
}

export class ClaudeOAuthManager {
	private credentials: ClaudeOAuthCredentials | null = null
	private refreshPromise: Promise<ClaudeOAuthCredentials> | null = null
	private pendingAuth: {
		codeVerifier: string
		state: string
		server?: http.Server
	} | null = null

	async loadCredentials(): Promise<ClaudeOAuthCredentials | null> {
		try {
			const stateManager = StateManager.get()
			const credentialsJson = stateManager.getSecretKey(CLAUDE_OAUTH_CREDENTIALS_KEY)
			if (!credentialsJson) return null
			const parsed = JSON.parse(credentialsJson)
			this.credentials = claudeOAuthCredentialsSchema.parse(parsed)
			return this.credentials
		} catch (error) {
			Logger.error("[claude-oauth] Failed to load credentials:", error)
			return null
		}
	}

	async saveCredentials(credentials: ClaudeOAuthCredentials): Promise<void> {
		const stateManager = StateManager.get()
		stateManager.setSecret(CLAUDE_OAUTH_CREDENTIALS_KEY, JSON.stringify(credentials))
		await stateManager.flushPendingState()
		this.credentials = credentials
	}

	async clearCredentials(): Promise<void> {
		const stateManager = StateManager.get()
		stateManager.setSecret(CLAUDE_OAUTH_CREDENTIALS_KEY, undefined)
		await stateManager.flushPendingState()
		this.credentials = null
	}

	async getAccessToken(): Promise<string | null> {
		if (!this.credentials) {
			await this.loadCredentials()
		}
		if (!this.credentials) return null

		if (isTokenExpired(this.credentials)) {
			try {
				if (!this.refreshPromise) {
					this.refreshPromise = refreshAccessToken(this.credentials)
				}
				const newCredentials = await this.refreshPromise
				this.refreshPromise = null
				await this.saveCredentials(newCredentials)
			} catch (error) {
				this.refreshPromise = null
				Logger.error("[claude-oauth] Failed to refresh token:", error)
				await this.clearCredentials()
				return null
			}
		}

		return this.credentials.access_token
	}

	async getEmail(): Promise<string | null> {
		if (!this.credentials) {
			await this.loadCredentials()
		}
		return this.credentials?.email ?? null
	}

	async isAuthenticated(): Promise<boolean> {
		if (!this.credentials) {
			await this.loadCredentials()
		}
		return this.credentials !== null
	}

	startAuthorizationFlow(): string {
		this.cancelAuthorizationFlow()

		const codeVerifier = generateCodeVerifier()
		const codeChallenge = generateCodeChallenge(codeVerifier)
		const state = generateState()

		this.pendingAuth = { codeVerifier, state }
		return buildAuthorizationUrl(codeChallenge, state)
	}

	async waitForCallback(): Promise<ClaudeOAuthCredentials> {
		if (!this.pendingAuth) {
			throw new Error("No pending authorization flow")
		}

		if (this.pendingAuth.server) {
			try {
				this.pendingAuth.server.close()
			} catch {
				// ignore
			}
			this.pendingAuth.server = undefined
		}

		return new Promise((resolve, reject) => {
			const server = http.createServer(async (req, res) => {
				try {
					const url = new URL(req.url || "", `http://localhost:${CLAUDE_OAUTH_CONFIG.callbackPort}`)

					if (url.pathname !== "/callback") {
						res.writeHead(404)
						res.end("Not Found")
						return
					}

					const code = url.searchParams.get("code")
					const state = url.searchParams.get("state")
					const error = url.searchParams.get("error")

					if (error) {
						res.writeHead(400)
						res.end(`Authentication failed: ${error}`)
						reject(new Error(`OAuth error: ${error}`))
						server.close()
						return
					}

					if (!code || !state) {
						res.writeHead(400)
						res.end("Missing code or state parameter")
						reject(new Error("Missing code or state parameter"))
						server.close()
						return
					}

					if (state !== this.pendingAuth?.state) {
						res.writeHead(400)
						res.end("State mismatch - possible CSRF attack")
						reject(new Error("State mismatch"))
						server.close()
						return
					}

					try {
						const credentials = await exchangeCodeForTokens(code, this.pendingAuth.codeVerifier, state)
						await this.saveCredentials(credentials)

						res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" })
						res.end(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authentication Successful</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    color: #fff;
  }
  .container { text-align: center; padding: 48px; max-width: 420px; }
  .icon {
    width: 72px; height: 72px; margin: 0 auto 24px;
    background: linear-gradient(135deg, #d97706 0%, #b45309 100%);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
  }
  .icon svg { width: 36px; height: 36px; stroke: #fff; stroke-width: 3; fill: none; }
  h1 { font-size: 24px; font-weight: 600; margin-bottom: 12px; }
  p { font-size: 15px; color: rgba(255,255,255,0.7); line-height: 1.5; }
  .closing { margin-top: 32px; font-size: 13px; color: rgba(255,255,255,0.5); }
</style>
</head>
<body>
<div class="container">
  <div class="icon">
    <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg>
  </div>
  <h1>Authentication Successful</h1>
  <p>You're now signed in with Claude. You can close this window and return to your IDE.</p>
  <p class="closing">This window will close automatically...</p>
</div>
<script>setTimeout(() => window.close(), 3000);</script>
</body>
</html>`)

						this.pendingAuth = null
						server.close()
						resolve(credentials)
					} catch (exchangeError) {
						res.writeHead(500)
						res.end(`Token exchange failed: ${exchangeError}`)
						reject(exchangeError)
						server.close()
					}
				} catch (err) {
					res.writeHead(500)
					res.end("Internal server error")
					reject(err)
					server.close()
				}
			})

			server.on("error", (err: NodeJS.ErrnoException) => {
				this.pendingAuth = null
				server.close()
				if (err.code === "EADDRINUSE") {
					reject(
						new Error(
							`Port ${CLAUDE_OAUTH_CONFIG.callbackPort} is already in use. ` +
								`Please close any other applications using this port and try again.`,
						),
					)
				} else {
					reject(err)
				}
			})

			const timeout = setTimeout(
				() => {
					server.close()
					reject(new Error("Authentication timed out"))
				},
				5 * 60 * 1000,
			)

			server.listen(CLAUDE_OAUTH_CONFIG.callbackPort, () => {
				if (this.pendingAuth) {
					this.pendingAuth.server = server
				}
			})

			server.on("close", () => {
				clearTimeout(timeout)
			})
		})
	}

	cancelAuthorizationFlow(): void {
		if (this.pendingAuth?.server) {
			this.pendingAuth.server.close()
		}
		this.pendingAuth = null
	}

	getCredentials(): ClaudeOAuthCredentials | null {
		return this.credentials
	}
}

export const claudeOAuthManager = new ClaudeOAuthManager()
