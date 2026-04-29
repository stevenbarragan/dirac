import { Anthropic } from "@anthropic-ai/sdk"
import { Tool as AnthropicTool } from "@anthropic-ai/sdk/resources/index"
import type { MessageCreateParamsStreaming as AnthropicMessageCreateParamsStreaming } from "@anthropic-ai/sdk/resources/messages/messages"
import { claudeOAuthDefaultModelId, claudeOAuthModels, ClaudeOAuthModelId, ModelInfo } from "@shared/api"
import { buildExternalBasicHeaders } from "@/services/EnvUtils"
import { claudeOAuthManager } from "@/integrations/claude-oauth/oauth"
import { DiracStorageMessage } from "@/shared/messages/content"
import { fetch } from "@/shared/net"
import { ApiHandler, CommonApiHandlerOptions } from "../index"
import { withRetry } from "../retry"
import { sanitizeAnthropicMessages } from "../transform/anthropic-format"
import { ApiStream } from "../transform/stream"

interface ClaudeOAuthHandlerOptions extends CommonApiHandlerOptions {
	apiModelId?: string
	thinkingBudgetTokens?: number
}

/**
 * ClaudeOAuthHandler - Uses Anthropic API with OAuth Bearer token authentication.
 *
 * Authenticates via claude.ai OAuth (Pro/Max subscription) and calls api.anthropic.com
 * using Authorization: Bearer <access_token> instead of x-api-key.
 */
export class ClaudeOAuthHandler implements ApiHandler {
	private options: ClaudeOAuthHandlerOptions
	private client: Anthropic | undefined
	private cachedToken: string | undefined

	constructor(options: ClaudeOAuthHandlerOptions) {
		this.options = options
	}

	private async ensureClient(): Promise<Anthropic> {
		const token = await claudeOAuthManager.getAccessToken()
		if (!token) {
			throw new Error("Not authenticated with Claude. Please sign in with your Claude Pro/Max account.")
		}
		if (!this.client || token !== this.cachedToken) {
			this.client = new Anthropic({
				authToken: token,
				defaultHeaders: buildExternalBasicHeaders(),
				fetch,
			})
			this.cachedToken = token
		}
		return this.client
	}

	@withRetry()
	async *createMessage(systemPrompt: string, messages: DiracStorageMessage[], tools?: AnthropicTool[]): ApiStream {
		const client = await this.ensureClient()
		const model = this.getModel()

		const budgetTokens = this.options.thinkingBudgetTokens || 0
		const nativeToolsOn = !!tools?.length
		const reasoningOn = (model.info.supportsReasoning ?? false) && budgetTokens !== 0

		let stream: AsyncIterable<Anthropic.RawMessageStreamEvent>

		if (model.info.supportsPromptCache) {
			const anthropicMessages = sanitizeAnthropicMessages(messages, true)
			const requestBody: AnthropicMessageCreateParamsStreaming = {
				model: model.id,
				max_tokens: model.info.maxTokens || 8096,
				system: [{ type: "text", text: systemPrompt, cache_control: { type: "ephemeral" } }],
				messages: anthropicMessages as any,
				stream: true,
				...(nativeToolsOn ? { tools: tools as any } : {}),
				...(reasoningOn ? { thinking: { type: "enabled", budget_tokens: budgetTokens } } : {}),
			}
			stream = await client.messages.create(requestBody)
		} else {
			const anthropicMessages = sanitizeAnthropicMessages(messages, false)
			const requestBody: AnthropicMessageCreateParamsStreaming = {
				model: model.id,
				max_tokens: model.info.maxTokens || 8096,
				system: systemPrompt,
				messages: anthropicMessages as any,
				stream: true,
				...(nativeToolsOn ? { tools: tools as any } : {}),
				...(reasoningOn ? { thinking: { type: "enabled", budget_tokens: budgetTokens } } : {}),
			}
			stream = await client.messages.create(requestBody)
		}

		for await (const chunk of stream) {
			switch (chunk.type) {
				case "message_start":
					yield {
						type: "usage",
						inputTokens: chunk.message.usage.input_tokens || 0,
						outputTokens: chunk.message.usage.output_tokens || 0,
						cacheWriteTokens: (chunk.message.usage as any).cache_creation_input_tokens,
						cacheReadTokens: (chunk.message.usage as any).cache_read_input_tokens,
					}
					break
				case "message_delta":
					yield {
						type: "usage",
						inputTokens: 0,
						outputTokens: chunk.usage.output_tokens || 0,
					}
					break
				case "content_block_start":
					if (chunk.content_block.type === "thinking") {
						yield { type: "reasoning", reasoning: chunk.content_block.thinking ?? "" }
					} else if (chunk.content_block.type === "text") {
						if (chunk.index > 0) {
							yield { type: "text", text: "\n" }
						}
						yield { type: "text", text: chunk.content_block.text }
					}
					break
				case "content_block_delta":
					if (chunk.delta.type === "thinking_delta") {
						yield { type: "reasoning", reasoning: chunk.delta.thinking }
					} else if (chunk.delta.type === "text_delta") {
						yield { type: "text", text: chunk.delta.text }
					}
					break
			}
		}
	}

	getModel(): { id: ClaudeOAuthModelId; info: ModelInfo } {
		const modelId = (this.options.apiModelId as ClaudeOAuthModelId) || claudeOAuthDefaultModelId
		const info = claudeOAuthModels[modelId] ?? claudeOAuthModels[claudeOAuthDefaultModelId]
		return { id: modelId, info }
	}
}
