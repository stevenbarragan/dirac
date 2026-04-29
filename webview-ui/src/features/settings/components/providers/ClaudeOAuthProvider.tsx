import { EmptyRequest } from "@shared/proto/dirac/common"
import { useSettingsStore } from "@/features/settings/store/settingsStore"
import { VSCodeButton } from "@vscode/webview-ui-toolkit/react"
import { useState } from "react"
import { ModelsServiceClient } from "@/shared/api/grpc-client"

export const ClaudeOAuthProvider = () => {
	const claudeOAuthIsAuthenticated = useSettingsStore((state) => state.claudeOAuthIsAuthenticated)
	const claudeOAuthEmail = useSettingsStore((state) => state.claudeOAuthEmail)
	const [isAuthenticating, setIsAuthenticating] = useState(false)
	const [error, setError] = useState<string | null>(null)

	const handleSignIn = async () => {
		setIsAuthenticating(true)
		setError(null)
		try {
			await ModelsServiceClient.authenticateClaudeOAuth(EmptyRequest.create({}))
		} catch (err) {
			setError(err instanceof Error ? err.message : "Authentication failed")
		} finally {
			setIsAuthenticating(false)
		}
	}

	const handleSignOut = async () => {
		setError(null)
		try {
			await ModelsServiceClient.signOutClaudeOAuth(EmptyRequest.create({}))
		} catch (err) {
			setError(err instanceof Error ? err.message : "Sign out failed")
		}
	}

	return (
		<div>
			<div style={{ marginBottom: "15px" }}>
				<p
					style={{
						fontSize: "12px",
						color: "var(--vscode-descriptionForeground)",
						marginBottom: "10px",
					}}>
					Sign in with your Claude account (Pro or Max subscription) to use Claude models without an API key.
				</p>
			</div>

			<div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
				{claudeOAuthIsAuthenticated ? (
					<div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
						<span style={{ fontSize: "12px" }}>
							Signed in as <strong>{claudeOAuthEmail || "Claude User"}</strong>
						</span>
						<VSCodeButton appearance="secondary" onClick={handleSignOut} style={{ height: "24px" }}>
							Sign Out
						</VSCodeButton>
					</div>
				) : (
					<VSCodeButton disabled={isAuthenticating} onClick={handleSignIn}>
						{isAuthenticating ? "Signing in..." : "Sign in with Claude"}
					</VSCodeButton>
				)}
				{error && (
					<p style={{ fontSize: "12px", color: "var(--vscode-errorForeground)", margin: 0 }}>{error}</p>
				)}
			</div>
		</div>
	)
}
