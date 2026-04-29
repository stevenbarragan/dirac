import { Empty, EmptyRequest } from "@shared/proto/dirac/common"
import { claudeOAuthManager } from "@/integrations/claude-oauth/oauth"
import { openExternal } from "@/utils/env"
import { Logger } from "@/shared/services/Logger"
import type { Controller } from "../index"

/**
 * Authenticates with Claude (claude.ai subscription) via OAuth
 * @param controller The controller instance
 * @param _request The empty request
 * @returns Empty response
 */
export async function authenticateClaudeOAuth(controller: Controller, _request: EmptyRequest): Promise<Empty> {
	try {
		Logger.log("[claude-oauth] Starting authentication flow...")

		const authUrl = claudeOAuthManager.startAuthorizationFlow()
		await openExternal(authUrl)

		Logger.log("[claude-oauth] Waiting for browser callback...")
		await claudeOAuthManager.waitForCallback()

		Logger.log("[claude-oauth] Authentication successful!")
		await controller.postStateToWebview()

		return Empty.create({})
	} catch (error) {
		Logger.error("[claude-oauth] Authentication failed:", error)
		throw error
	}
}
