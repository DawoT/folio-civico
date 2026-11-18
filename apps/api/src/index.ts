import { authenticateAccess, type AccessConfig } from "@folio/auth";
import { getCommissionSummary } from "@folio/data";

export interface ApiEnv extends AccessConfig {
  DB?: D1Database;
}

function json(body: unknown, status: number): Response {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
  });
}

export async function handleApiRequest(request: Request, env: ApiEnv): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/health" && request.method === "GET") {
    return json({ status: "ok" }, 200);
  }

  const route = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/summary$/.exec(url.pathname);
  if (!route) return json({ error: "Not found" }, 404);
  if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);

  const subject = await authenticateAccess(request, env);
  if (!subject) return json({ error: "Unauthorized" }, 401);
  if (!env.DB) return json({ error: "Service not configured" }, 503);

  try {
    const summary = await getCommissionSummary(env.DB, subject, route[1]!);
    // Same response for nonexistent and unauthorized resources.
    return summary ? json(summary, 200) : json({ error: "Not found" }, 404);
  } catch {
    return json({ error: "Request could not be completed" }, 503);
  }
}

export default {
  fetch(request: Request, env: ApiEnv) {
    return handleApiRequest(request, env);
  }
} satisfies ExportedHandler<ApiEnv>;
