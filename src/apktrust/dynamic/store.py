import json, sqlite3
from pathlib import Path
from .models import DynamicJob, DynamicJobStatus, DynamicError, serial
class DynamicStore:
    def __init__(self,path):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.connection() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS dynamic_jobs (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, provider TEXT NOT NULL, status TEXT NOT NULL, record TEXT NOT NULL, config TEXT NOT NULL, consent_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS dynamic_executions (job_id TEXT PRIMARY KEY, result TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS dynamic_artifacts (job_id TEXT NOT NULL, id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(job_id,id));
            CREATE TABLE IF NOT EXISTS dynamic_observations (job_id TEXT NOT NULL, id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(job_id,id));
            CREATE INDEX IF NOT EXISTS dynamic_scan_jobs ON dynamic_jobs(scan_id);
            ''')
    def connection(self):
        conn=sqlite3.connect(self.path,timeout=15);self.path.chmod(0o600);return conn
    def create(self,job,config,consent_at):
        with self.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            # Prevent duplicate remote jobs while a scan is already running.
            active=c.execute("SELECT status FROM dynamic_jobs WHERE scan_id=?",(job.scan_id,)).fetchall()
            from .models import TERMINAL
            if any(DynamicJobStatus(row[0]) not in TERMINAL for row in active):raise DynamicError('UPLOAD_FAILED','This scan already has an active dynamic job')
            c.execute('INSERT INTO dynamic_jobs VALUES (?,?,?,?,?,?,?)',(job.id,job.scan_id,job.provider,job.status,json.dumps(serial(job)),json.dumps(config),consent_at))
    def save(self,job):
        with self.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT record FROM dynamic_jobs WHERE id=?',(job.id,)).fetchone()
            if row:
                old=json.loads(row[0]);known={(e['timestamp'],e['stage']) for e in job.events}
                job.events=sorted(job.events+[e for e in old['events'] if (e['timestamp'],e['stage']) not in known],key=lambda e:e['timestamp'])[-200:]
                if old['audit'].get('cancellation_requested_at'):job.audit.setdefault('cancellation_requested_at',old['audit']['cancellation_requested_at'])
            c.execute('UPDATE dynamic_jobs SET status=?,record=? WHERE id=?',(job.status,json.dumps(serial(job)),job.id))
    def get(self,id):
        with self.connection() as c:row=c.execute('SELECT record FROM dynamic_jobs WHERE id=?',(id,)).fetchone()
        if not row:return None
        data=json.loads(row[0]);data['status']=DynamicJobStatus(data['status'])
        if data.get('error'):data['error']=DynamicError(**data['error'])
        return DynamicJob(**data)
    def config(self,id):
        with self.connection() as c:row=c.execute('SELECT config FROM dynamic_jobs WHERE id=?',(id,)).fetchone()
        return json.loads(row[0]) if row else None
    def list(self,scan_id=None):
        with self.connection() as c:
            rows=c.execute('SELECT record FROM dynamic_jobs'+(' WHERE scan_id=?' if scan_id else '')+' ORDER BY rowid DESC',(scan_id,) if scan_id else ()).fetchall()
        return [json.loads(r[0]) for r in rows]
    def result(self,id):
        with self.connection() as c:row=c.execute('SELECT result FROM dynamic_executions WHERE job_id=?',(id,)).fetchone()
        return json.loads(row[0]) if row else None
    def complete(self,job,result):
        from .correlation import correlate
        data=serial(result)
        with self.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            c.execute('INSERT OR REPLACE INTO dynamic_executions VALUES (?,?)',(job.id,json.dumps(data)))
            for table,items in [('dynamic_artifacts',data['artifacts']),('dynamic_observations',data['observations'])]:
                for item in items:c.execute(f'INSERT OR REPLACE INTO {table} VALUES (?,?,?)',(job.id,item['id'],json.dumps(item)))
            # Refresh the report inside the transaction so concurrent analyst reviews are preserved.
            row=c.execute('SELECT report FROM scans WHERE id=?',(job.scan_id,)).fetchone()
            if row:c.execute('UPDATE scans SET report=? WHERE id=?',(json.dumps(correlate(json.loads(row[0]),data)),job.scan_id))
            c.execute('UPDATE dynamic_jobs SET status=?,record=? WHERE id=?',(job.status,json.dumps(serial(job)),job.id))
