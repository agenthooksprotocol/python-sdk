#!/usr/bin/env python3
"""Offline actual HTTP wire adapter; no expected outcomes or semantic controls."""
import base64, hashlib, json, os, sys, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request
from urllib.error import HTTPError
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from agent_hooks_protocol.interop import open_local, validate_upload_framing, validate_descriptor, replace_references, wire_request, loads
from agent_hooks_protocol.runtime import Validator
from agent_hooks_protocol.elicitation import validate_exchange, read_selected, selection, apply_effects, validate_mode


def main():
    if sys.argv[1] == 'client':
        plan=json.load(sys.stdin); results=[]; references={}; validator=Validator(); upload_failed=False
        for step in plan['steps']:
            credential = plan.get('uploadToken') if step['path']=='/upload' else plan['token']
            headers={**({'Authorization':'Bearer '+credential} if credential else {}), **step.get('headers',{})}
            raw=base64.b64decode(step['bytes'],validate=True)
            if step['path']=='/hooks/intercept':
                if upload_failed:raise ValueError('Dependent event suppressed after upload failure')
                raw=json.dumps(wire_request(replace_references(loads(raw),references))).encode()
            req=Request(plan['endpoint']+step['path'], data=raw,headers=headers,method='POST')
            try: response=open_local(req)
            except HTTPError as error: response=error
            with response:
                if step['path']=='/upload' and response.status==201:
                    descriptor=validate_descriptor(response,raw,validator)
                    if 'ref' in step:references[step['ref']]=descriptor
                    body=json.dumps(descriptor)
                else:
                    if step['path']=='/upload':upload_failed=True
                    body=response.read(4*1024*1024+1).decode()
                results.append({'status':response.status,'body':body})
        print(json.dumps(results)); return
    schemas={p.stem.removesuffix('.schema'):json.loads(p.read_text()) for p in Path(sys.argv[2]).glob('*.schema.json')}
    registry=Registry().with_resources((s['$id'],Resource.from_contents(s)) for s in schemas.values())
    def validate(name,value):
        if name == "form-answer":
            Draft202012Validator(value["schema"],format_checker=FormatChecker()).validate(value["value"]);return
        file,_,fragment=name.partition('#')
        schema=schemas[file] if not fragment else {'$ref':schemas[file]['$id']+'#/$defs/'+fragment}
        Draft202012Validator(schema,registry=registry,format_checker=FormatChecker()).validate(value)
    token=os.environ['AHP_ELICITATION_TOKEN']; principal=sys.argv[3]
    store={};pending={};receipts=[]
    def resolve(ref):
        validate('content-reference',ref)
        raw=store[ref['ref']]
        if len(raw)!=ref['size'] or hashlib.sha256(raw).hexdigest()!=ref['sha256']:raise ValueError('Upload integrity')
        return raw
    if sys.argv[1] == 'check':
        outputs=[]
        for case in json.load(sys.stdin):
            snapshot=json.dumps(case,sort_keys=True)
            store.clear()
            for upload in case.get('uploads', []):store[upload['ref']]=base64.b64decode(upload['bytes'])
            try:
                if case.get('op') == 'capability':
                    summary=validate_mode(case['mode'],case.get('capabilities'),case.get('origin','ahp'))
                elif case.get('op') == 'apply':
                    before=json.dumps(case,sort_keys=True)
                    try: summary=apply_effects(case['request'],case.get('result'),resolve,validate,principal,case['effects'])
                    finally:
                        if json.dumps(case,sort_keys=True)!=before: raise RuntimeError('Input mutated')
                else: summary=validate_exchange(case['request'],case['result'],resolve,validate,principal,case.get('effect'))
                outputs.append({'accepted':True,'summary':summary})
            except Exception:outputs.append({'accepted':False})
            if case.get('op')=='apply':outputs[-1]['inputUnchanged']=json.dumps(case,sort_keys=True)==snapshot
        print(json.dumps(outputs));return
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_): pass
        def do_POST(self):
            credential=os.environ.get('AHP_ELICITATION_UPLOAD_TOKEN') if self.path=='/upload' else token
            if not credential or len(self.headers.get_all('Authorization', [])) != 1 or self.headers.get('Authorization')!='Bearer '+credential:
                self.send_response(401);self.end_headers();return
            try:
                size=int(self.headers.get('Content-Length','0'))
                if size<0 or size>4*1024*1024:raise ValueError('Size limit')
                self.connection.settimeout(10)
                raw=self.rfile.read(size)
                if len(raw)!=size:raise ValueError('length')
                if self.path=='/upload':
                    validate_upload_framing(self.headers,raw)
                    ref='urn:uuid:'+str(uuid.uuid4())
                    store[ref]=raw; status=201;response={'ref':ref,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
                elif self.path=='/receipts':status=200;response=receipts
                elif self.path=='/hooks/intercept':
                    message=loads(raw);validate('intercept-request',message)
                    event=message['params']['event'];meta=event['elicitation']
                    parent=event['id'] if event['type']=='user.elicitation.request' else event['parentEventId']
                    key=(event['source'],parent)
                    if message['id']!=event['id']:raise ValueError('ID mismatch')
                    if event['type']=='user.elicitation.request':
                        if key in pending:raise ValueError('Duplicate pending request identity')
                        validate_mode(meta['mode'], {'form':{},'url':{}})
                        payload=read_selected(meta,'request',resolve,validate)
                        body=resolve(meta['request']['body']) if payload is not None else b''
                        pending[key]=message;summary={'request':payload} if payload is not None else {'selection':selection(meta,'request')}
                    elif event['type']=='user.elicitation.result':
                        summary=validate_exchange(pending[key],message,resolve,validate,principal)
                        body=resolve(meta['result']['body']) if meta.get('result',{}).get('body') else b'';del pending[key]
                    else:raise ValueError('Not elicitation')
                    receipts.append({'message':message,'bytes':base64.b64encode(body).decode(),'summary':summary})
                    status=200;response={'jsonrpc':'2.0','id':message['id'],'result':{'protocolVersion':'draft','effects':[]}}
                else:raise ValueError('Unknown endpoint')
            except Exception:
                status=400;response={'error':'rejected'}
            self.send_response(status);self.send_header('Content-Type','application/json');self.end_headers()
            if response is not None:self.wfile.write(json.dumps(response).encode())
    server=HTTPServer(('127.0.0.1',0),Handler)
    print(json.dumps({'endpoint':'http://127.0.0.1:'+str(server.server_port)}),flush=True)
    server.serve_forever()
if __name__=='__main__':main()
