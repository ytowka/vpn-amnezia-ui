"""Persistent single-use invitations. Tokens are returned once, only hashes stored."""
import contextlib
import hashlib
import re
import secrets
import sqlite3
import time
from pathlib import Path

class GuestError(Exception):
    def __init__(self, message, status=400, retry=0):
        super().__init__(message)
        self.status, self.retry = status, retry

class Invitations:
    def __init__(self, directory):
        self.path = Path(directory)/'guests.sqlite3'
    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS invites (
                id TEXT PRIMARY KEY, digest TEXT UNIQUE NOT NULL, created INTEGER NOT NULL,
                expires INTEGER NOT NULL, status TEXT NOT NULL, device TEXT, used INTEGER);
              CREATE TABLE IF NOT EXISTS attempts (
                ip TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0, window INTEGER NOT NULL, requests INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS global_rate (id INTEGER PRIMARY KEY, window INTEGER, requests INTEGER);
            ''')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
    def create(self, hours):
        if type(hours) is not int or hours not in (1,24,168):
            raise GuestError('Срок действия: 1 час, 24 часа или 7 дней')
        token = secrets.token_urlsafe(32)
        now, ident = int(time.time()), secrets.token_hex(8)
        with self.db() as db:
            if db.execute("SELECT count(*) FROM invites WHERE status='active' AND expires>?",(now,)).fetchone()[0]>=100:
                raise GuestError('Сначала отзовите лишние ключи: разрешено 100 активных')
            db.execute('INSERT INTO invites VALUES (?,?,?,?,?,?,?)',
                       (ident,hashlib.sha256(token.encode()).hexdigest(),now,now+hours*3600,'active',None,None))
        return {'id':ident,'key':token,'expires':now+hours*3600}
    def listing(self):
        with self.db() as db:
            rows=db.execute('SELECT id,created,expires,status,device,used FROM invites ORDER BY created DESC, rowid DESC LIMIT 200').fetchall()
        return [dict(r, status='expired' if r['status']=='active' and r['expires']<=time.time() else r['status']) for r in rows]
    def revoke(self, ident):
        with self.db() as db:
            result=db.execute("UPDATE invites SET status='revoked' WHERE id=? AND status='active'",(ident,))
            if not result.rowcount: raise GuestError('Этот ключ уже использован, отозван или выдаётся')
    def throttle(self, ip):
        now=int(time.time())
        error=None
        with self.db() as db:
            # Limit persistent storage; keep current cooldowns when cleaning old IPs.
            db.execute('DELETE FROM attempts WHERE window<? AND blocked<?',(now-86400,now))
            row=db.execute('SELECT * FROM attempts WHERE ip=?',(ip,)).fetchone()
            if row and row['blocked']>now:
                error=GuestError('Слишком много неверных попыток. Попробуйте позже.',429,row['blocked']-now)
            else:
                count=row['requests'] if row and now-row['window']<60 else 0
                window=row['window'] if row and now-row['window']<60 else now
                failures=row['failures'] if row and now-row['window']<900 and not row['blocked'] else 0
                db.execute('INSERT OR REPLACE INTO attempts VALUES (?,?,?,?,?)',(ip,failures,0,window,count+1))
                total=db.execute('SELECT * FROM global_rate WHERE id=1').fetchone()
                global_count=total['requests'] if total and now-total['window']<60 else 0
                global_window=total['window'] if total and now-total['window']<60 else now
                db.execute('INSERT OR REPLACE INTO global_rate VALUES (1,?,?)',(global_window,global_count+1))
                if count>=10 or global_count>=120:
                    error=GuestError('Лимит запросов. Подождите минуту.',429,60)
        if error: raise error
    def claim(self, token, name, ip):
        self.throttle(ip)
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,39}',name):
            raise GuestError('Имя: латинские буквы, цифры, _ и -, до 40 символов')
        now=int(time.time())
        digest=hashlib.sha256(token.encode()).hexdigest() if isinstance(token,str) and len(token)<=128 else ''
        invalid=False
        result=None
        with self.db() as db:
            row=db.execute("SELECT * FROM invites WHERE digest=? AND status='active' AND expires>?",(digest,now)).fetchone()
            if not row:
                invalid=True
                attempt=db.execute('SELECT * FROM attempts WHERE ip=?',(ip,)).fetchone()
                failures=attempt['failures']+1
                db.execute('UPDATE attempts SET failures=?,blocked=? WHERE ip=?',(failures,now+900 if failures>=5 else 0,ip))
            else:
                device=name+'-g-'+secrets.token_hex(6)
                db.execute("UPDATE invites SET status='issuing',device=?,used=? WHERE id=?",(device,now,row['id']))
                db.execute('UPDATE attempts SET failures=0,blocked=0 WHERE ip=?',(ip,))
                result={'id':row['id'],'device':device}
        if invalid: raise GuestError('Ключ недействителен, истёк или уже использован',403)
        return result
    def finish(self, ident, success):
        with self.db() as db:
            db.execute("UPDATE invites SET status=? WHERE id=? AND status='issuing'",('used' if success else 'failed',ident))
    def redeem(self, token, name, ip, provision):
        claim=self.claim(token,name,ip)
        # Reservation is committed BEFORE provisioning: concurrent requests/crashes
        # cannot issue a second peer. A lost response is recovered only by admin.
        try:
            config=provision(claim['device'])
        except Exception:
            self.finish(claim['id'],False)
            raise GuestError('Выдача не завершена. Обратитесь к администратору; повторно использовать ключ нельзя.',503)
        self.finish(claim['id'],True)
        return claim['device'],config
