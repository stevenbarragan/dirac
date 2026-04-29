import { Empty, EmptyRequest } from "@shared/proto/dirac/common"
import { claudeOAuthManager } from "@/integrations/claude-oauth/oauth"
import { Logger } from "@/shared/services/Logger"
import type { Controller } from "../index"

/**
 * Signs out from Claude OAuth
 * @param controller The controller instance
 * @param _request The empty request
 * @returns Empty response
 */
export async function signOutClaudeOAuth(controller: Controller, _request: EmptyRequest): Promise<Empty> {
	try {
		Logger.log("[claude-oauth] Signing out...")
		await claudeOAuthManager.clearCredentials()
		await controller.postStateToWebview()
		return Empty.create({})
	} catch (error) {
		Logger.error("[claude-oauth] Sign out failed:", error)
		throw error
	}
}
