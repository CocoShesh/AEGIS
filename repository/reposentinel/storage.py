import json, os, sqlite3
from pathlib import Path
from .core import now
DATA=Path(os.environ.get('REPOSENTINEL_DATA',str(Path(__file__).resolve().parent.parent/'.data')))
def connect():
    DATA.mkdir(parents=True,exist_ok=True,mode=0o700)
    db=sqlite3.connect(DATA/'scans.sqlite',timeout=15)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, state TEXT NOT NULL, detail TEXT, created_at TEXT, report TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS ai_commentary (scan_id TEXT PRIMARY KEY, payload TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS reviews (scan_id TEXT, finding_id TEXT, disposition TEXT, note TEXT, updated_at TEXT, PRIMARY KEY(scan_id,finding_id))')
    return db

def update(scan_id,state,detail='',report=None):
    with connect() as db:
        db.execute('INSERT INTO scans VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state, detail=excluded.detail, report=COALESCE(excluded.report, scans.report)',(scan_id,state,detail,now(),json.dumps(report) if report else None))

def get(scan_id):
    with connect() as db:
        row=db.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
        if not row: return None
        obj=dict(row); obj['report']=json.loads(obj['report']) if obj['report'] else None
        if obj['report']:
            ai=db.execute('SELECT payload FROM ai_commentary WHERE scan_id=?',(scan_id,)).fetchone()
            if ai:
                obj['report']['ai_explanation']=json.loads(ai['payload'])
                file_reviews={x['id']:x for x in obj['report']['ai_explanation'].get('file_reviews',[])}
                for f in obj['report'].get('files',[]):
                    if f['id'] in file_reviews:f['ai_review']=file_reviews[f['id']]
                for run in obj['report'].get('scanner_runs',[]):
                    if run['engine']=='AI review':run.update(status='COMPLETED',detail='Optional AI commentary generated; separate from scanner evidence')
            reviews={r['finding_id']:dict(r) for r in db.execute('SELECT * FROM reviews WHERE scan_id=?',(scan_id,))}
            for f in obj['report']['findings']: f['review']=reviews.get(f['id'])
        return obj

def history():
    with connect() as db: rows=db.execute('SELECT id,state,detail,created_at,report FROM scans ORDER BY created_at DESC LIMIT 100').fetchall()
    out=[]
    for row in rows:
        r=dict(row); report=json.loads(r.pop('report') or '{}'); r['repository']=report.get('repository'); r['findings']=len(report.get('findings',[])); r['coverage']=report.get('coverage'); out.append(r)
    return out

def review(scan_id,finding_id,disposition,note):
    with connect() as db: db.execute('INSERT OR REPLACE INTO reviews VALUES (?,?,?,?,?)',(scan_id,finding_id,disposition,note,now()))

def save_ai(scan_id,payload):
    with connect() as db:db.execute('INSERT OR REPLACE INTO ai_commentary VALUES (?,?)',(scan_id,json.dumps(payload)))

def remove(scan_id):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT state FROM scans WHERE id=?',(scan_id,)).fetchone()
        if row is None:return 'missing'
        if row['state'] not in ('PARTIAL','COMPLETED','FAILED','CANCELLED','LIMIT_EXCEEDED'):return 'active'
        db.execute('DELETE FROM reviews WHERE scan_id=?',(scan_id,))
        db.execute('DELETE FROM ai_commentary WHERE scan_id=?',(scan_id,))
        db.execute('DELETE FROM scans WHERE id=?',(scan_id,))
    return 'removed'
