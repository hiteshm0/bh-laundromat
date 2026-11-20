// Drive an isolated Chrome profile through its DevTools pipe. No browser add-ons required.
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
const [chrome, directory, url] = process.argv.slice(2);
const browser = spawn(chrome, ["--headless=new", "--disable-gpu", "--disable-background-networking",
  "--disable-component-update", "--no-first-run", "--remote-debugging-pipe",
  "--user-data-dir=" + path.join(directory, "chrome"), "about:blank"],
  {stdio:["ignore","ignore","ignore","pipe","pipe"]});
let counter = 0, buffer = "";
const pending = new Map();
const errors = [];
browser.stdio[4].setEncoding("utf8");
browser.stdio[4].on("data", chunk => {
  buffer += chunk;
  for (let end; (end=buffer.indexOf("\0")) !== -1;) {
    const message=JSON.parse(buffer.slice(0,end));
    buffer=buffer.slice(end+1);
    if(message.method === "Runtime.exceptionThrown") errors.push(message.params.exceptionDetails.text);
    const request=pending.get(message.id);
    if(request) {
      pending.delete(message.id);
      if(message.error) request.reject(Error(message.error.message));
      else request.resolve(message.result);
    }
  }
});
const call=(method,params={},sessionId) => new Promise((resolve,reject)=>{
  const id=++counter;
  pending.set(id,{resolve,reject});
  browser.stdio[3].write(JSON.stringify({id,method,params,sessionId})+"\0");
});
const timeout=setTimeout(()=>{process.stderr.write("Browser check timed out\n");browser.kill();process.exit(2);},60000);
try {
  const {targetId}=await call("Target.createTarget",{url:"about:blank"});
  const {sessionId}=await call("Target.attachToTarget",{targetId,flatten:true});
  const send=(method,params)=>call(method,params,sessionId);
  await send("Runtime.enable");
  await send("Page.enable");
  async function contains(text) {
    for(let i=0;i<120;i++) {
      const result=await send("Runtime.evaluate",{expression:"document.body?.innerText || ''",returnByValue:true});
      if(result.result.value.includes(text)) return;
      await delay(200);
    }
    throw Error("Missing rendered text: "+text);
  }
  await send("Page.navigate",{url});
  await contains("Determining changed files");
  await send("Page.reload",{ignoreCache:true});
  await contains("Determining changed files");
  fs.writeFileSync(path.join(directory,"continue"),"");
  await contains("Review finished");
  await contains("Repair evidence");
  await send("Page.reload",{ignoreCache:true});
  await contains("Review finished");
  if(errors.length) throw Error(errors.join(", "));
  console.log("Rendered capturing detail, refreshed it, observed completion in place, refreshed completed review.");
} finally {
  clearTimeout(timeout);
  browser.kill();
}
