# SPDX-License-Identifier: AGPL-3.0-or-later
"""Registered, restricted WCS count evaluation using the existing Java kernel."""
import base64
import hashlib
import json
import subprocess
from pathlib import Path
from source import instant
from state import RULE, canonical, digest, hexid

FIELDS={'event.kind','event.category','event.action','event.outcome','source.ip','destination.ip','user.id'}


def scalar(value):
    return isinstance(value,str) and bool(value.strip()) and len(value)<=1024


def field(doc,name):
    value=doc
    for part in name.split('.'):
        if not isinstance(value,dict) or part not in value:
            return None
        value=value[part]
    return value


def definition(store,job):
    id=digest('wade-rule-revision-v1',store.tenant,job['rule_id'],job['rule_version'])
    rule=store._read(RULE,id)['_source']
    if rule['rule_id']!=job['rule_id'] or rule['rule_version']!=job['rule_version']:
        raise ValueError('registered rule identity mismatch')
    raw=base64.b64decode(rule['selector_payload'],validate=True)
    if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=hexid(rule['selector_digest']):
        raise ValueError('selector integrity')
    if rule['mode'] not in ('EVENT_COUNT','DISTINCT_VALUE_COUNT') or type(rule['threshold']) is not int or type(rule['max_inputs']) is not int or not 1<=rule['threshold']<=rule['max_inputs']<=10000:
        raise ValueError('invalid rule limits')
    if rule['definition_digest']!=digest('wade-rule-v1',store.tenant,job['rule_id'],job['rule_version'],rule['mode'],str(rule['threshold']),str(rule['max_inputs']),rule['selector_digest']):
        raise ValueError('definition integrity')
    selector=json.loads(raw)
    if raw!=canonical(selector).encode() or set(selector)!={'format','scope_field','terms','distinct_field'} or selector['format']!='wcs-count-v1' or selector['scope_field']!='agent.id' or job['entity_type']!='agent':
        raise ValueError('unsupported selector or scope')
    terms=selector['terms']
    if not isinstance(terms,dict) or not 1<=len(terms)<=8 or terms.get('event.kind')!='event' or any(k not in FIELDS or not scalar(v) for k,v in terms.items()):
        raise ValueError('unsupported terms')
    distinct=selector['distinct_field']
    if (rule['mode']=='EVENT_COUNT' and distinct is not None) or (rule['mode']=='DISTINCT_VALUE_COUNT' and distinct not in FIELDS):
        raise ValueError('unsupported distinct field')
    return rule,selector


def encode(fields):
    return b''.join(base64.urlsafe_b64encode(str(f).encode()).rstrip(b'=')+b'\n' for f in fields)


def decode(raw):
    return [base64.b64decode(line+b'='*((-len(line))%4),altchars=b'-_',validate=True).decode() for line in raw.splitlines()]


class RegisteredCountEvaluator:
    """Explicit trusted local Java classpath; no shell, no user-supplied executable."""
    def __init__(self,store,classpath,*,timeout=10):
        self.store=store; self.classpath=str(Path(classpath).resolve(strict=True)); self.timeout=timeout
        if not 1<=timeout<=60: raise ValueError('invalid evaluator timeout')

    def __call__(self,job,rows,end,as_of):
        rule,selector=definition(self.store,job)
        if len(rows)>10000: return {'status':'UNKNOWN'}
        entries=[]; references={}; input_hashes=[]
        for row in rows:
            if row['tenant']!=self.store.tenant: raise ValueError('foreign evidence')
            doc=row['source']; agent=field(doc,'agent.id')
            if not scalar(agent): return {'status':'UNKNOWN'}
            if agent!=job['entity_id']: continue
            checks=[]
            for name,wanted in selector['terms'].items():
                actual=field(doc,name)
                if scalar(actual): checks.append(actual==wanted)
                elif isinstance(actual,list) and actual and all(scalar(x) for x in actual): checks.append(wanted in actual)
                else: checks.append(None)
            ref=(row['index_uuid'],row['document_id'])
            event_time=doc['@timestamp']; available=field(doc,'event.ingested')
            if not instant(job['checkpoint'])<=instant(event_time)<instant(end) or not instant(event_time)<=instant(available)<=instant(as_of):
                raise ValueError('non-causal evidence')
            if False in checks:
                input_hashes.append(digest(*ref,event_time,available,'NO_MATCH')); continue
            if None in checks: return {'status':'UNKNOWN'}
            value='' if selector['distinct_field'] is None else field(doc,selector['distinct_field'])
            if selector['distinct_field'] is not None and not scalar(value): return {'status':'UNKNOWN'}
            if ref in references: return {'status':'UNKNOWN'}
            references[ref]={'index_name':row['index_name'],'index_uuid':ref[0],'document_id':ref[1]}
            entries.extend((*ref,event_time,value))
            input_hashes.append(digest(*ref,event_time,available,'MATCH',value))
        fields=['wade-count-bridge-v1',self.store.tenant,job['entity_type'],job['entity_id'],job['rule_id'],job['rule_version'],rule['mode'],rule['threshold'],rule['max_inputs'],job['checkpoint'],end,end,'COMPLETE',len(references),*entries]
        data=encode(fields)
        if len(data)>4*1024*1024: return {'status':'UNKNOWN'}
        proc=subprocess.run(['java','-Xmx128m','-cp',self.classpath,'com.wazuh.wade.NativeCountBridge'],input=data,capture_output=True,timeout=self.timeout,check=True)
        if len(proc.stdout)>4*1024*1024: raise ValueError('bridge output limit')
        out=decode(proc.stdout)
        status=out[0]
        if status in ('UNKNOWN','NOT_READY'): return {'status':status}
        if status not in ('MATCH','NO_MATCH') or len(out)<2: raise ValueError('invalid bridge outcome')
        receipt=digest('wade-native-count-receipt-v1',rule['definition_digest'],job['job_id'],job['checkpoint'],end,as_of,*sorted(input_hashes),*out)
        result={'schema_version':1,'tenant':self.store.tenant,'rule_id':job['rule_id'],'rule_version':job['rule_version'],'entity_type':job['entity_type'],'entity_id':job['entity_id'],'window_start':job['checkpoint'],'window_end':end,'as_of':as_of,'rule_digest':rule['definition_digest'],'receipt_id':receipt,'status':status}
        if status=='MATCH':
            count,n=int(out[4]),int(out[5]); refs=list(zip(out[6::2],out[7::2]))
            if len(out)!=6+2*n or len(refs)!=n or len(set(refs))!=n or set(refs)!=set(references) or not 1<=count<=n:
                raise ValueError('invalid bridge evidence')
            result.update(finding_id=hexid(out[2]),evidence_digest=hexid(out[3]),observed_count=count,sources=[references[r] for r in refs])
        elif len(out)!=2: raise ValueError('unexpected negative output')
        return result
