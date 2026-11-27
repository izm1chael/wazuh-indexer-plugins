# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local SQLite append-only feature and risk ledger; not an Indexer adapter."""
import json
import sqlite3
from source import instant
from state import canonical, digest, hexid
from intelligence import key


class Ledger:
    def __init__(self, path, tenant):
        self.tenant=key(tenant)
        self.db=sqlite3.connect(path,timeout=5)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS history (
            tenant TEXT NOT NULL, kind TEXT NOT NULL, scope TEXT NOT NULL, version TEXT NOT NULL,
            id TEXT NOT NULL, available TEXT NOT NULL, body TEXT NOT NULL, checksum TEXT NOT NULL,
            PRIMARY KEY(tenant,kind,scope,version,id))''')
        self.db.execute('CREATE INDEX IF NOT EXISTS history_cutoff ON history(tenant,kind,scope,version,available,id)')
        self.db.commit()

    def close(self): self.db.close()

    def _partition(self,kind,scope,version):
        if kind not in ('FEATURE','RISK_SIGNAL','ALIAS','RELATION'): raise ValueError('unsupported ledger kind')
        return (self.tenant,kind,key(scope),key(version))

    def append(self, kind, scope, version, id, available, body):
        partition=self._partition(kind,scope,version); hexid(id)
        if not isinstance(body,dict) or body.get('tenant')!=self.tenant: raise ValueError('foreign or invalid body')
        time=instant(available).isoformat(timespec='microseconds')
        payload=canonical(body)
        if len(payload.encode())>65536: raise ValueError('record budget')
        checksum=digest('wade-history-v1',*partition,id,time,payload)
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO history VALUES(?,?,?,?,?,?,?,?)',(*partition,id,time,payload,checksum))
            prior=self.db.execute('SELECT available,body,checksum FROM history WHERE tenant=? AND kind=? AND scope=? AND version=? AND id=?',(*partition,id)).fetchone()
            if prior!=(time,payload,checksum): raise ValueError('immutable history conflict')
        return checksum

    def snapshot(self,kind,scope,version,as_of,*,limit=1000):
        partition=self._partition(kind,scope,version)
        if type(limit) is not int or not 1<=limit<=10000: raise ValueError('invalid snapshot limit')
        cutoff=instant(as_of).isoformat(timespec='microseconds')
        rows=self.db.execute('SELECT id,available,body,checksum FROM history WHERE tenant=? AND kind=? AND scope=? AND version=? AND available<=? ORDER BY available,id LIMIT ?',(*partition,cutoff,limit+1))
        records=[]; total=0
        for id,time,body,checksum in rows:
            total+=len(body.encode())
            if len(records)>=limit or total>8*1024*1024: return {'status':'UNKNOWN','reason':'INPUT_LIMIT','records':[]}
            if digest('wade-history-v1',*partition,id,time,body)!=checksum: raise ValueError('history integrity failure')
            parsed=json.loads(body)
            if parsed.get('tenant')!=self.tenant: raise ValueError('history scope failure')
            records.append({'id':id,'available':time,'body':parsed,'checksum':checksum})
        # An exhaustive local query is not proof of complete external telemetry.
        return {'status':'SNAPSHOT','records':records,'receipt':digest('wade-history-snapshot-v1',*partition,cutoff,*(r['checksum'] for r in records))}
