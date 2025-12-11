import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  InvalidTokenError,
  InsufficientScopeError,
  ServerError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { withAuthContext } from "./auth-context";

declare global {
  interface Request {
    auth?: AuthInfo;
  }
}

/**
 * Interface for tool-level scope error data that may be embedded in JSON-RPC error responses.
 * This is used to detect scope escalation errors that occurred inside tool handlers.
 */
export interface ToolScopeErrorData {
  required_scopes?: string[];
  auth_url?: string;
}

/**
 * Check if a JSON-RPC error response indicates a tool-level scope error.
 * Tool handlers may return scope errors in the error.data field.
 */
function isToolScopeError(responseBody: unknown): responseBody is {
  error: {
    code: number;
    message: string;
    data?: ToolScopeErrorData;
  };
} {
  if (typeof responseBody !== 'object' || responseBody === null) return false;

  const body = responseBody as Record<string, unknown>;
  if (typeof body.error !== 'object' || body.error === null) return false;

  const error = body.error as Record<string, unknown>;
  const data = error.data as Record<string, unknown> | undefined;

  // Check for scope-related error patterns
  const message = String(error.message || '').toLowerCase();
  const hasRequiredScopes = Array.isArray(data?.required_scopes);
  const hasScopeKeyword = message.includes('scope') || message.includes('permission');

  return hasRequiredScopes || hasScopeKeyword;
}

/**
 * Build WWW-Authenticate header for tool-level scope errors per RFC 6750 / MCP spec 4.1.1
 */
function buildToolScopeWWWAuthenticate(
  scopeData: ToolScopeErrorData,
  message: string,
  resourceMetadataUrl: string
): string {
  const scope = scopeData.required_scopes?.join(" ") || "";

  const parts = [
    `Bearer error="insufficient_scope"`,
    scope ? `scope="${scope}"` : null,
    `resource_metadata="${resourceMetadataUrl}"`,
    `error_description="${message}"`,
  ].filter(Boolean);

  return parts.join(", ");
}

/**
 * Create HTTP 403 response for tool-level scope errors per MCP spec section 4.1.1
 */
function createToolScopeResponse(
  error: { code: number; message: string; data?: ToolScopeErrorData },
  resourceMetadataUrl: string
): Response {
  const wwwAuthenticate = buildToolScopeWWWAuthenticate(
    error.data || {},
    error.message,
    resourceMetadataUrl
  );

  return new Response(
    JSON.stringify({
      error: "insufficient_scope",
      error_description: error.message,
      required_scopes: error.data?.required_scopes || [],
      auth_url: error.data?.auth_url,
    }),
    {
      status: 403,
      headers: {
        "Content-Type": "application/json",
        "WWW-Authenticate": wwwAuthenticate,
      },
    }
  );
}

export function withMcpAuth(
  handler: (req: Request) => Response | Promise<Response>,
  verifyToken: (
    req: Request,
    bearerToken?: string
  ) => AuthInfo | undefined | Promise<AuthInfo | undefined>,
  {
    required = false,
    resourceMetadataPath = "/.well-known/oauth-protected-resource",
    requiredScopes,
    interceptToolScopeErrors = true,
  }: {
    required?: boolean;
    resourceMetadataPath?: string;
    requiredScopes?: string[];
    /** 
     * If true, intercept JSON-RPC error responses from tool handlers 
     * that indicate scope errors and convert them to HTTP 403 responses.
     * This enables runtime scope escalation per MCP spec section 4.1.1.
     * @default true
     */
    interceptToolScopeErrors?: boolean;
  } = {}
) {
  return async (req: Request) => {
    const origin = new URL(req.url).origin;
    const resourceMetadataUrl = `${origin}${resourceMetadataPath}`;

    const authHeader = req.headers.get("Authorization");
    const [type, token] = authHeader?.split(" ") || [];

    // Only support bearer token as per the MCP spec
    // https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization#2-6-1-token-requirements
    const bearerToken = type?.toLowerCase() === "bearer" ? token : undefined;

    let authInfo: AuthInfo | undefined;
    try {
      authInfo = await verifyToken(req, bearerToken);
    } catch (error) {
      console.error("Unexpected error authenticating bearer token:", error);
      const publicError = new InvalidTokenError("Invalid token");
      return new Response(JSON.stringify(publicError.toResponseObject()), {
        status: 401,
        headers: {
          "WWW-Authenticate": `Bearer error="${publicError.errorCode}", error_description="${publicError.message}", resource_metadata="${resourceMetadataUrl}"`,
          "Content-Type": "application/json",
        },
      });
    }

    try {
      if (required && !authInfo) {
        throw new InvalidTokenError("No authorization provided");
      }

      if (!authInfo) {
        const response = await handler(req);
        // Still check for tool scope errors even without auth (could be optional auth)
        if (interceptToolScopeErrors) {
          return await maybeConvertToolScopeError(response, resourceMetadataUrl);
        }
        return response;
      }

      // Check if token has the required scopes (if any)
      if (requiredScopes?.length) {
        const hasAllScopes = requiredScopes.every((scope) =>
          authInfo!.scopes.includes(scope)
        );

        if (!hasAllScopes) {
          throw new InsufficientScopeError("Insufficient scope");
        }
      }

      // Check if the token is expired
      if (authInfo.expiresAt && authInfo.expiresAt < Date.now() / 1000) {
        throw new InvalidTokenError("Token has expired");
      }

      // Set auth info on the request object after successful verification
      req.auth = authInfo;

      // Execute the handler and intercept the response for tool-level scope errors
      const response = await withAuthContext(authInfo, () => handler(req));

      if (interceptToolScopeErrors) {
        return await maybeConvertToolScopeError(response, resourceMetadataUrl);
      }

      return response;
    } catch (error) {
      if (error instanceof InvalidTokenError) {
        return new Response(JSON.stringify(error.toResponseObject()), {
          status: 401,
          headers: {
            "WWW-Authenticate": `Bearer error="${error.errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`,
            "Content-Type": "application/json",
          },
        });
      } else if (error instanceof InsufficientScopeError) {
        return new Response(JSON.stringify(error.toResponseObject()), {
          status: 403,
          headers: {
            "WWW-Authenticate": `Bearer error="${error.errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`,
            "Content-Type": "application/json",
          },
        });
      } else if (error instanceof ServerError) {
        return new Response(JSON.stringify(error.toResponseObject()), {
          status: 500,
          headers: {
            "Content-Type": "application/json",
          },
        });
      } else {
        console.error("Unexpected error authenticating bearer token:", error);
        const serverError = new ServerError("Internal Server Error");
        return new Response(JSON.stringify(serverError.toResponseObject()), {
          status: 500,
          headers: {
            "Content-Type": "application/json",
          },
        });
      }
    }
  };
}

/**
 * Check if a response contains a tool-level scope error and convert it to HTTP 403 if so.
 * This intercepts JSON-RPC error responses from tool handlers that indicate scope escalation.
 * 
 * Handles three cases:
 * 1. JSON-RPC error response: { error: { code, message, data } }
 * 2. Tool result with error: { result: { isError: true, content: [...] } }
 * 3. SSE stream containing scope error events
 */
async function maybeConvertToolScopeError(
  response: Response,
  resourceMetadataUrl: string
): Promise<Response> {
  console.log("[withMcpAuth] maybeConvertToolScopeError called, status:", response.status);

  // Only check 200 responses (JSON-RPC errors/results are returned as 200)
  if (response.status !== 200) {
    console.log("[withMcpAuth] Skipping - status is not 200");
    return response;
  }

  // Check content type
  const contentType = response.headers.get("content-type") || "";
  console.log("[withMcpAuth] Content-Type:", contentType);

  // Handle SSE (text/event-stream) responses
  if (contentType.includes("text/event-stream")) {
    return maybeConvertSseToolScopeError(response, resourceMetadataUrl);
  }

  // Handle JSON responses
  if (!contentType.includes("application/json")) {
    console.log("[withMcpAuth] Skipping - content-type is not JSON or SSE");
    return response;
  }

  // Clone the response to read the body without consuming it
  const clonedResponse = response.clone();

  try {
    const body = await clonedResponse.json();
    console.log("[withMcpAuth] Response body:", JSON.stringify(body).slice(0, 500));

    // Case 1: JSON-RPC error response
    if (isToolScopeError(body)) {
      console.log("[withMcpAuth] Detected tool-level scope error (JSON-RPC error), converting to HTTP 403");
      return createToolScopeResponse(body.error, resourceMetadataUrl);
    }

    // Case 2: Tool result with isError: true
    // When a tool throws McpError, the SDK converts it to a result with isError flag
    if (isToolResultScopeError(body)) {
      console.log("[withMcpAuth] Detected tool-level scope error (tool result), converting to HTTP 403");
      const scopeData = extractScopeDataFromToolResult(body);
      return createToolScopeResponse(
        {
          code: -32600,
          message: scopeData.message,
          data: scopeData.data,
        },
        resourceMetadataUrl
      );
    }

    console.log("[withMcpAuth] No scope error detected in response");
  } catch (err) {
    // If we can't parse the body, just return the original response
    console.log("[withMcpAuth] Error parsing response body:", err);
  }

  return response;
}

/**
 * Handle SSE (Server-Sent Events) responses and check for scope errors.
 * SSE events have the format:
 *   event: message
 *   data: {"jsonrpc": "2.0", ...}
 */
async function maybeConvertSseToolScopeError(
  response: Response,
  resourceMetadataUrl: string
): Promise<Response> {
  console.log("[withMcpAuth] Processing SSE stream for scope errors");

  // Clone the response to read without consuming
  const clonedResponse = response.clone();

  try {
    // Read the entire SSE body (this may not work well for true streaming, but works for buffered responses)
    const sseText = await clonedResponse.text();
    console.log("[withMcpAuth] SSE content (first 500 chars):", sseText.slice(0, 500));

    // Parse SSE events - they are in the format:
    // event: message
    // data: {...json...}
    // 
    // Events are separated by double newlines
    const events = sseText.split(/\n\n+/);

    for (const event of events) {
      if (!event.trim()) continue;

      // Find the data line(s)
      const lines = event.split('\n');
      let jsonData = '';

      for (const line of lines) {
        if (line.startsWith('data:')) {
          // Remove "data:" prefix and trim
          jsonData += line.slice(5).trim();
        }
      }

      if (!jsonData) continue;

      try {
        const body = JSON.parse(jsonData);
        console.log("[withMcpAuth] Parsed SSE event:", JSON.stringify(body).slice(0, 300));

        // Check for scope errors in this event
        if (isToolScopeError(body)) {
          console.log("[withMcpAuth] Detected tool-level scope error in SSE (JSON-RPC error), converting to HTTP 403");
          return createToolScopeResponse(body.error, resourceMetadataUrl);
        }

        if (isToolResultScopeError(body)) {
          console.log("[withMcpAuth] Detected tool-level scope error in SSE (tool result), converting to HTTP 403");
          const scopeData = extractScopeDataFromToolResult(body);
          return createToolScopeResponse(
            {
              code: -32600,
              message: scopeData.message,
              data: scopeData.data,
            },
            resourceMetadataUrl
          );
        }
      } catch {
        // Not valid JSON, skip this event
        console.log("[withMcpAuth] Could not parse SSE event as JSON:", jsonData.slice(0, 100));
      }
    }

    console.log("[withMcpAuth] No scope error found in SSE stream");
  } catch (err) {
    console.log("[withMcpAuth] Error processing SSE stream:", err);
  }

  // Return the original response if no scope error found
  return response;
}

/**
 * Check if a JSON-RPC response is a tool result with scope error.
 * Tool errors from McpError become: { result: { isError: true, content: [...] } }
 */
function isToolResultScopeError(responseBody: unknown): boolean {
  if (typeof responseBody !== 'object' || responseBody === null) return false;

  const body = responseBody as Record<string, unknown>;
  const result = body.result as Record<string, unknown> | undefined;

  if (!result || result.isError !== true) return false;

  const content = result.content as Array<{ type: string; text?: string }> | undefined;
  if (!Array.isArray(content)) return false;

  // Check if any text content contains scope-related error indicators
  for (const item of content) {
    if (item.type === 'text' && typeof item.text === 'string') {
      const text = item.text.toLowerCase();
      // Look for scope-related keywords
      if (text.includes('scope') || text.includes('permission') || text.includes('unauthorized')) {
        return true;
      }
      // Try to parse as JSON and check for required_scopes
      try {
        const parsed = JSON.parse(item.text);
        if (parsed.required_scopes || parsed.auth_url) {
          return true;
        }
      } catch {
        // Not JSON, continue
      }
    }
  }

  return false;
}

/**
 * Extract scope error data from a tool result response.
 */
function extractScopeDataFromToolResult(responseBody: Record<string, unknown>): {
  message: string;
  data: ToolScopeErrorData;
} {
  const result = responseBody.result as Record<string, unknown>;
  const content = result.content as Array<{ type: string; text?: string }>;

  let message = "Insufficient scope";
  let data: ToolScopeErrorData = {};

  for (const item of content) {
    if (item.type === 'text' && typeof item.text === 'string') {
      // Try to parse as JSON first
      try {
        const parsed = JSON.parse(item.text);
        if (parsed.required_scopes) {
          data.required_scopes = parsed.required_scopes;
        }
        if (parsed.auth_url) {
          data.auth_url = parsed.auth_url;
        }
        if (parsed.message) {
          message = parsed.message;
        }
      } catch {
        // Not JSON, use the text as the message
        message = item.text;
      }
    }
  }

  return { message, data };
}
