const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
async function flush(){for(let i=0;i<16;i++)await Promise.resolve();}
function harness(template) {
  const source=fs.readFileSync(`webui/templates/${template}`, 'utf8');
  const loader=source.match(/async function loadAccounts\(\) \{[\s\S]*?\n\}\nasync function pollAccountPlanStatuses/)[0].replace(/\nasync function pollAccountPlanStatuses$/, '');
  const requests=[],renders=[],timers=new Map(),toasts=[];
  let nextTimer=0;
  const context=vm.createContext({
    SHOW_ARCHIVED_ACCOUNTS:false,ACCOUNTS:[],ACCOUNTS_TOTAL:0,PAGERS:{accounts:{page:1,size:20}},AbortController,
    getAccountsPlanFilter:()=>'',getAccountsCodexFilter:()=>'',getAccountsTotpFilter:()=>'',getAccountsQuery:()=>'',
    document:{getElementById:()=>null},$:()=>null,
    setTimeout(fn){timers.set(++nextTimer,fn);return nextTimer;},clearTimeout(id){timers.delete(id);},
    api(url,options){return new Promise((resolve,reject)=>{
      requests.push({url,resolve,reject});options?.signal?.addEventListener('abort',()=>reject(new Error('aborted')));
    });},
    renderAccounts(){renders.push(vm.runInContext('ACCOUNTS.map(a=>a.id).join(",")',context));},
    showToast(message){toasts.push(message);},
  });
  const run=code=>vm.runInContext(code,context);
  run('let accountsLoading=false;let accountsReloadPending=false;'+loader);
  return {run,requests,renders,timers,toasts,
    async resolve(i,value){requests[i].resolve(value);await flush();},
    async reject(i){requests[i].reject(new Error('offline'));await flush();},
    async expire(){for(const fn of [...timers.values()])fn();await flush();},
  };
}
(async()=>{
  for(const template of ['index.html','index_legacy.html']) {
    // The real api(), when cancelled after the response headers have arrived while the body is being read, must also throw, and must not swallow it into a successful empty object.
    const source=fs.readFileSync(`webui/templates/${template}`, 'utf8');
    const apiSource=source.match(/async function api\(url, opts\) \{[\s\S]*?\n\}/)[0];
    const controller=new AbortController();
    const apiContext=vm.createContext({fetch:async()=>({ok:true,json:async()=>{controller.abort();throw new Error('body aborted');}})});
    vm.runInContext(apiSource,apiContext);
    await assert.rejects(apiContext.api('/api/accounts',{signal:controller.signal}),/body aborted/);
    // A refresh after deletion must not be swallowed by an old list request that is still loading, let alone re-render the deleted account.
    const h=harness(template);h.run('loadAccounts();loadAccounts();loadAccounts()');
    assert.equal(h.requests.length,1);
    await h.resolve(0,{items:[{id:2}],total:1});
    assert.equal(h.renders.length,0,`${template}: stale pre-delete list rendered`);
    assert.equal(h.requests.length,2,`${template}: post-delete refresh lost`);
    assert.equal(h.run('accountsLoading'),true);
    await h.resolve(1,{items:[],total:0});
    assert.deepEqual(h.renders,['']);assert.equal(h.run('accountsLoading'),false);
    // After the page count shrinks, the last page is re-read automatically, and the lock stays in effect during the re-read.
    h.run('PAGERS.accounts.page=9;loadAccounts()');
    await h.resolve(2,{items:[],total:21});
    assert.match(h.requests[3].url,/page=2&/);assert.equal(h.run('accountsLoading'),true);
    h.run('loadAccounts()');assert.equal(h.requests.length,4);
    await h.resolve(3,{items:[{id:21}],total:21});
    assert.equal(h.requests.length,5);assert.equal(h.run('accountsLoading'),true);
    await h.resolve(4,{items:[{id:21}],total:21});
    assert.equal(h.run('accountsLoading'),false);
    // A failed or timed-out old request must also release the lock and run the merged refresh request.
    h.run('loadAccounts();loadAccounts()');await h.reject(5);
    assert.equal(h.requests.length,7);await h.resolve(6,{items:[],total:0});
    h.run('loadAccounts();loadAccounts()');await h.expire();
    assert.equal(h.requests.length,9);assert.equal(h.run('accountsLoading'),true);
    await h.resolve(8,{items:[],total:0});
    assert.equal(h.timers.size,0);assert.equal(h.run('accountsLoading'),false);
  }
  console.log('New and old account list regression passed: refresh merging after deletion, old-response discard, shrink-page re-read lock, failure/timeout recovery.');
})().catch(error=>{console.error(error);process.exitCode=1;});
