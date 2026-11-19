import { DurableObject } from "cloudflare:workers";
import {
  handleInspectorGatewayRequest, type InspectorGatewaySecrets
} from "./route";

interface GatewayEnv extends InspectorGatewaySecrets {
  /** Populated only by the operator-approved Containers config. */
  INSPECTOR_CONTAINER?: DurableObjectNamespace<InspectorContainer>;
}

const PORT=8789;
const READY_CHECKS=40;
const INACTIVITY_MS=2*60*1000;
const INSTANCE_NAME="folio-private-inspector-singleton";

/**
 * Dedicated Cloudflare Container adapter. The standard Wrangler configuration
 * deliberately omits its binding and image. Even a dry-run cannot start a
 * container, so this Worker is fail-closed until approved Preview resources
 * and secrets are explicitly configured.
 */
export class InspectorContainer extends DurableObject<GatewayEnv> {
  private starting?:Promise<void>;

  private async startAndWait():Promise<void> {
    const c=this.ctx.container;
    if(!c)throw new Error("No container binding configured");
    const token=this.env.INSPECTOR_SERVICE_TOKEN;
    const signing=this.env.INSPECTOR_HMAC_KEY;
    if(!token || token.length<32 || !signing || signing.length<32) {
      throw new Error("Inspector secrets are not configured");
    }
    if(!c.running) {
      c.start({
        image:c.images.base,
        instance:"standard-1",
        enableInternet:false,
        env:{
          FOLIO_INSPECTOR_SERVICE_TOKEN:token,
          FOLIO_INSPECTOR_OUTPUT_MODE:"unsigned",
          CLAMAV_DB_DIR:"/opt/clamdb"
        }
      });
    }
    await c.setInactivityTimeout(INACTIVITY_MS);
    const port=c.getTcpPort(PORT);
    for(let check=0;check<READY_CHECKS;check++){
      try {
        const health=await port.fetch("http://container/health",{
          signal:AbortSignal.timeout(1000)
        });
        await health.body?.cancel();
        if(health.ok)return;
      }catch{
        // The container might still be booting, but never allow traffic
        // before an explicit readiness check.
      }
      await scheduler.wait(250);
    }
    throw new Error("Private inspector container is not ready");
  }

  async fetch(request:Request):Promise<Response> {
    // The gateway performs full validation; direct Durable Object callers
    // must still present the unforgeable service token.
    const url=new URL(request.url);
    if(request.method!=="POST" || url.pathname!=="/inspect" || url.search
      || !this.env.INSPECTOR_SERVICE_TOKEN
      || request.headers.get("X-Folio-Inspector-Token")!==this.env.INSPECTOR_SERVICE_TOKEN) {
      return new Response(null,{status:403,headers:{"Cache-Control":"no-store"}});
    }
    try {
      this.starting??=this.startAndWait().finally(()=>{this.starting=undefined;});
      await this.starting;
      const target=new URL(request.url);
      target.protocol="http:";
      target.host="container";
      const forwarded=new Request(target,request);
      forwarded.headers.delete("host");
      return await this.ctx.container!.getTcpPort(PORT).fetch(forwarded);
    }catch{
      return new Response(null,{status:503,headers:{"Cache-Control":"no-store"}});
    }
  }
}

export default {
  fetch(request:Request,env:GatewayEnv):Promise<Response> {
    return handleInspectorGatewayRequest(request,env,async verified=>{
      if(!env.INSPECTOR_CONTAINER)throw new Error("Container not provisioned");
      return env.INSPECTOR_CONTAINER.getByName(INSTANCE_NAME).fetch(verified);
    });
  }
} satisfies ExportedHandler<GatewayEnv>;
