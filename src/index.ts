import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createServer } from "./server";

async function verifyToken(token: string): Promise<boolean> {
  const response = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await response.json() as { success: boolean };
  return data.success === true;
}

function extractToken(authHeader: string): string | null {
  const match = authHeader.match(/Bearer\s+(\S+)/);
  return match ? match[1] : null;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const authHeader = request.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Authorization header required" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const token = extractToken(authHeader);
    if (!token) {
      return new Response(JSON.stringify({ error: "Invalid Authorization header format" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const isValid = await verifyToken(token);
    if (!isValid) {
      return new Response(JSON.stringify({ error: "Invalid Cloudflare API token" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const server = createServer(env, token);

    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    await server.connect(transport);
    const response = await transport.handleRequest(request);
    ctx.waitUntil(transport.close());

    return response;
  },
};
