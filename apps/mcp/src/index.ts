import { authenticateAccess, type AccessConfig } from "@folio/auth";
import { getCommissionSummary } from "@folio/data";
import { createMcpHandler } from "agents/mcp/server";
import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

export interface McpEnv extends AccessConfig {
  DB?: D1Database;
}

function createServer(subject: string, db: D1Database) {
  const server = new McpServer({
    name: "folio-civico",
    version: "0.1.0"
  });

  server.registerTool("get_commission_summary", {
    description: "Read the status of a commission the signed-in member belongs to.",
    inputSchema: z.object({ commissionId: z.string().min(1).max(64).regex(/^[A-Za-z0-9_-]+$/) })
  }, async ({ commissionId }) => {
    try {
      const summary = await getCommissionSummary(db, subject, commissionId);
      if (!summary) {
        return { isError: true, content: [{ type: "text" as const, text: "Commission not found or inaccessible" }] };
      }
      return { content: [{ type: "text" as const, text: JSON.stringify(summary) }] };
    } catch {
      return { isError: true, content: [{ type: "text" as const, text: "Unable to retrieve commission" }] };
    }
  });

  return server;
}

export async function handleMcpRequest(
  request: Request,
  env: McpEnv,
  context: ExecutionContext
): Promise<Response> {
  if (new URL(request.url).pathname !== "/mcp") {
    return new Response("Not found", { status: 404 });
  }

  const subject = await authenticateAccess(request, env);
  if (!subject) {
    return new Response("Unauthorized", {
      status: 401, headers: { "Cache-Control": "no-store", "WWW-Authenticate": "Bearer" }
    });
  }
  if (!env.DB) return new Response("Service not configured", { status: 503 });

  const handler = createMcpHandler(() => createServer(subject, env.DB!));
  return handler(request, env, context);
}

export default {
  fetch(request: Request, env: McpEnv, context: ExecutionContext) {
    return handleMcpRequest(request, env, context);
  }
} satisfies ExportedHandler<McpEnv>;
