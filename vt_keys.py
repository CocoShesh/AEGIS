"""Bounded fallback across locally configured VT credentials, with no secret output."""
import hashlib, threading, time

VARIABLES=('VT_API_KEY','VT_API_KEY_2','VT_API_KEY_3')
def configured_keys(config):
    return list(dict.fromkeys(config.get(name,'').strip() for name in VARIABLES if config.get(name,'').strip()))

class VTKeyPool:
    def __init__(self,clock=time.time):
        self.clock=clock;self.gate=threading.Lock();self.lock=threading.Lock()
        self.cooldowns={};self.disabled=set();self.preferred=None
    @staticmethod
    def identity(key):return hashlib.sha256(key.encode()).hexdigest()
    def snapshot(self,keys):
        with self.lock:
            return [{'slot':i+1,'status':'AUTH_REJECTED' if self.identity(k) in self.disabled else 'COOLDOWN' if self.cooldowns.get(self.identity(k),0)>self.clock() else 'AVAILABLE','retry_at':self.cooldowns.get(self.identity(k),0) if self.cooldowns.get(self.identity(k),0)>self.clock() else None} for i,k in enumerate(keys)]
    def run(self,keys,call,error_type):
        keys=list(dict.fromkeys(keys))
        if not keys:raise error_type('VirusTotal API key is not configured')
        # Serialize VT requests across workers; status reads use a separate lock.
        with self.gate:
            with self.lock:
                candidates=[k for k in keys if self.identity(k) not in self.disabled and self.cooldowns.get(self.identity(k),0)<=self.clock()]
                candidates.sort(key=lambda k:self.identity(k)!=self.preferred)
            for key in candidates:
                try:value=call(key)
                except error_type as error:
                    code=getattr(error,'http_status',None)
                    if code is None:
                        text=str(error);code=429 if text.startswith('HTTP 429') else 401 if text.startswith('HTTP 401') else None
                    if code not in (401,429):raise
                    with self.lock:
                        ident=self.identity(key)
                        if code==401:self.disabled.add(ident)
                        else:self.cooldowns[ident]=self.clock()+max(1,getattr(error,'retry_after',None) or 900)
                    continue
                with self.lock:self.preferred=self.identity(key)
                return value
            with self.lock:rate_limited=any(self.cooldowns.get(self.identity(k),0)>self.clock() for k in keys)
            if rate_limited:raise error_type('HTTP 429: All configured VirusTotal keys are cooling down; reputation is temporarily unavailable; retry after cooldown or provider quota reset')
            raise error_type('HTTP 401: All configured VirusTotal keys were rejected; check local credentials')
