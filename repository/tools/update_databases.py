"""Refresh public advisory caches; no repository is passed to either command."""
import os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
CACHE=ROOT/'.scanner-cache';CACHE.mkdir(exist_ok=True)
env={'PATH':'/usr/bin:/bin','HOME':str(CACHE),'LANG':'C.UTF-8','GRYPE_DB_CACHE_DIR':str(CACHE/'grype'),'GRYPE_CHECK_FOR_APP_UPDATE':'false','GRYPE_DB_UPDATE_DOWNLOAD_TIMEOUT':'120s','GRYPE_DB_UPDATE_AVAILABLE_TIMEOUT':'20s'}
commands=[('Trivy',[str(ROOT/'.tools/bin/trivy'),'fs','--download-db-only','--cache-dir',str(CACHE/'trivy'),'--config',str(ROOT/'rules/scanner-config.yaml'),'--disable-telemetry','--quiet','--timeout','120s']),('Grype',[str(ROOT/'.tools/bin/grype'),'db','update','--config',str(ROOT/'rules/scanner-config.yaml'),'--quiet'])]
for label,cmd in commands:
 try:
  subprocess.run(cmd,env=env,cwd=ROOT,timeout=600,check=True)
  if label=='Grype':
   # A newly fetched database must not inherit a manual import's build date.
   (CACHE/'grype-provenance.json').unlink(missing_ok=True)
  print(label+': advisory cache updated',flush=True)
 except (OSError,subprocess.SubprocessError):print(label+': cache update failed; scan coverage will report unavailable/stale DB instead of clean',flush=True)
