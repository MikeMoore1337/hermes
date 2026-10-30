// Disposable network-none image fixture only; no paired agent or host mounts.
import fs from 'node:fs';
import {callTool, listTools} from '/app/dist/dispatcher.js';
const need=(value,reason)=>{if(!value)throw new Error(reason);};
need(process.getuid()===65534,'non-root');
for(const name of ['get_config','set_config_value','get_recent_tool_calls',
 'prepare_file_transfer','send_file_transfer','receive_file_transfer']){
 need(!listTools().some(tool=>tool.name===name),'denied-catalog');
 need((await callTool(name,{})).isError===true,'denied-dispatch');
}
const path='/workspace/edit-fixture.txt';
const before='same\nsame\nunique-before\n';
const written=await callTool('write_file',{path,content:before,mode:'rewrite'});
need(written.isError!==true&&fs.readFileSync(path,'utf8')===before,'fixture-write');
const conflict=await callTool('edit_block',{
 file_path:path,old_string:'same',new_string:'wrong',expected_replacements:1,
});
need(conflict.isError===true&&fs.readFileSync(path,'utf8')===before,'conflict-error-no-write');
const unique=await callTool('edit_block',{
 file_path:path,old_string:'unique-before',new_string:'unique-after',expected_replacements:1,
});
need(unique.isError!==true&&fs.readFileSync(path,'utf8')==='same\nsame\nunique-after\n','unique-edit');
fs.unlinkSync(path);
console.log('H454_EDIT_IMAGE_SMOKE=PASS');
process.exit(0);
