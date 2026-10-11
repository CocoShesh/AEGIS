"""Exercise runtime UI states without a browser or any provider requests."""
import shutil, subprocess, unittest
from pathlib import Path

@unittest.skipUnless(shutil.which('node'), 'Node is required for JavaScript UI checks')
class DynamicUITests(unittest.TestCase):
    def test_not_run_and_provider_durations(self):
        source=Path(__file__).resolve().parents[1]/'web'/'dynamic.js'
        script=r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const ctx={state:{},esc:String,tag:String,icon:()=>''};vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),ctx);
const job={status:'NOT_RUN',stage:'Completed with gaps',device:{},audit:{test_timeout_seconds:300},events:[],error:{code:'APK_INCOMPATIBLE',message:'No device'}};
const result={coverage:'LIMITED',analysis_gaps:['Not executed'],provider_metadata:{run_durations:[]}};
const html=ctx.dynamicExecution(job,result);
assert(html.includes('Execution not started'));
assert(html.includes('No runtime evidence was collected'));
assert(html.includes('300 seconds'));
assert(html.includes('Actual duration: Not run'));
assert(!html.includes('LIMITED'));assert(!html.includes('Actual duration: []'));
assert(!html.includes('Completed with gaps'));
job.status='COMPLETED';
assert.equal(ctx.dynamicDuration(job,result),'Not reported by provider');
result.provider_metadata.run_durations=[{seconds:'300',nanos:0}];
assert.equal(ctx.dynamicDuration(job,result),'5m 0s');
result.provider_metadata.run_durations=[{seconds:'59',nanos:900000000}];
assert.equal(ctx.dynamicDuration(job,result),'1m 0s');
result.provider_metadata.run_durations=[{seconds:'invalid'}];
assert.equal(ctx.dynamicDuration(job,result),'Not reported by provider');
result.provider_metadata.run_durations=[7];
assert.equal(ctx.dynamicDuration(job,result),'Not reported by provider');
'''
        subprocess.run(['node','-e',script,str(source)],check=True,capture_output=True,text=True,timeout=10)
