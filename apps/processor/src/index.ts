import {processBatch,type ProcessorEnv} from "./consumer";

export default {
  async queue(batch:MessageBatch<unknown>,env:ProcessorEnv):Promise<void>{
    const result=await processBatch(batch,env);
    console.log(JSON.stringify({kind:"folio.processing.queue",...result}));
  }
} satisfies ExportedHandler<ProcessorEnv>;
