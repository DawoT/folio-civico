import { authenticateAccess, type AccessConfig } from "@folio/auth";
import { getCommissionSummary, listAccessibleCommissions, listCommissionBatches, listChecklist } from "@folio/data";
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

  server.registerTool("list_my_commissions", {
    description: "List only the commissions assigned to the authenticated user.",
    inputSchema: z.object({})
  }, async () => {
    try {
      const items = await listAccessibleCommissions(db, subject);
      return { content: [{ type: "text" as const, text: JSON.stringify(items) }] };
    } catch {
      return { isError: true, content: [{ type: "text" as const, text: "Unable to list commissions" }] };
    }
  });

  server.registerTool("list_commission_batches", {
    description: "List batches only for a commission assigned to the authenticated user.",
    inputSchema: z.object({ commissionId: z.string().min(1).max(64).regex(/^[A-Za-z0-9_-]+$/) })
  }, async ({ commissionId }) => {
    try {
      const commission = await getCommissionSummary(db, subject, commissionId);
      if (!commission) {
        return { isError: true, content: [{ type: "text" as const, text: "Commission not found or inaccessible" }] };
      }
      const batches = await listCommissionBatches(db, subject, commissionId);
      return { content: [{ type: "text" as const, text: JSON.stringify(batches) }] };
    } catch {
      return { isError: true, content: [{ type: "text" as const, text: "Unable to list commission batches" }] };
    }
  });

  server.registerTool("get_checklist_status", {
    description: "Read only the checklist for an assigned commission. A pending item is not a finding of irregularity.",
    inputSchema: z.object({commissionId:z.string().min(1).max(64).regex(/^[A-Za-z0-9_-]+$/)})
  }, async ({commissionId}) => {
    try {
      const commission=await getCommissionSummary(db,subject,commissionId);
      if (!commission) return {
        isError:true,content:[{type:"text" as const,text:"Commission not found or inaccessible"}]
      };
      const items=await listChecklist(db,subject,commissionId);
      return {content:[{type:"text" as const,text:JSON.stringify({commissionId,items})}]};
    } catch {
      return {isError:true,content:[{type:"text" as const,text:"Unable to retrieve checklist"}]};
    }
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

  // The MVP MCP endpoint is server-to-server only. Reject browser Origins and
  // disable all CORS responses to avoid browser-driven requests with Access cookies.
  if (request.headers.has("Origin")) return new Response("Forbidden", {
    status: 403, headers: { "Cache-Control": "no-store" }
  });

  const subject = await authenticateAccess(request, env);
  if (!subject) {
    return new Response("Unauthorized", {
      status: 401, headers: { "Cache-Control": "no-store", "WWW-Authenticate": "Bearer" }
    });
  }
  if (!env.DB) return new Response("Service not configured", { status: 503 });

  const handler = createMcpHandler(() => createServer(subject, env.DB!), {
    corsOptions: false,
    legacy: "reject"
  });
  return handler(request, env, context);
}

export default {
  fetch(request: Request, env: McpEnv, context: ExecutionContext) {
    return handleMcpRequest(request, env, context);
  }
} satisfies ExportedHandler<McpEnv>;
