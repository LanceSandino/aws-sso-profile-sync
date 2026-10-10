# Compiled CLI regression for same-name synthetic accounts and read-only planning.
# Uses only a disposable HOME, synthetic cache and loopback SDK endpoints.
import atexit,hashlib,json,os,pathlib,shutil,subprocess,tempfile,threading
from http.server import BaseHTTPRequestHandler,HTTPServer
root=pathlib.Path(tempfile.mkdtemp(prefix='aws-sso-p03-acceptance-',dir=os.environ.get('TMPDIR','/tmp')))
atexit.register(shutil.rmtree, root)
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/assignment/accounts'):body={'accountList':[{'accountId':'111111111111','accountName':'Same Name'},{'accountId':'222222222222','accountName':'Same Name'}]}
        elif self.path.startswith('/assignment/roles'):body={'roleList':[{'roleName':'AWSReadOnlyAccess'}]}
        else:self.send_error(404);return
        self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(body).encode())
    def log_message(self,*args):pass
server=HTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
endpoint=f'http://127.0.0.1:{server.server_port}';session={'name':'same-name-fixture','start_url':'https://synthetic.invalid/start','sso_region':'us-east-1'}
identity=json.dumps({'Session':session,'Endpoint':endpoint},separators=(',',':')).encode();auth=root/'state'/'auth';auth.mkdir(parents=True,mode=0o700)
cache=auth/(hashlib.sha256(identity).hexdigest()+'.json');cache.write_text(json.dumps({'accessToken':'synthetic-p03','expiresAt':'2030-01-01T00:00:00Z','registrationExpiresAt':'2030-01-01T00:00:00Z','clientId':'synthetic-client','clientSecret':'test-only-synthetic-secret','session':session,'endpoint':endpoint}));cache.chmod(0o600)
env={k:v for k,v in os.environ.items() if not k.startswith('AWS_')};env.update(HOME=str(root),AWS_CONFIG_FILE=str(root/'config'),AWS_SHARED_CREDENTIALS_FILE=str(root/'credentials'),AWS_ACCESS_KEY_ID='test',AWS_SECRET_ACCESS_KEY='test',AWS_EC2_METADATA_DISABLED='true',GOENV='off',GOFLAGS='',GOCACHE=os.environ.get('GOCACHE',str(pathlib.Path(tempfile.gettempdir())/'aws-sso-sync-build')),GOMODCACHE=os.environ.get('GOMODCACHE',str(pathlib.Path(tempfile.gettempdir())/'aws-sso-sync-mod')))
binary=root/'aws-sso-profile-sync';subprocess.run(['go','build','-o',str(binary),'./cmd/aws-sso-profile-sync'],env=env,check=True,timeout=60)
def snapshot():return {str(p.relative_to(root)):(p.stat().st_mode,p.stat().st_mtime_ns,hashlib.sha256(p.read_bytes()).hexdigest()) for p in root.rglob('*') if p.is_file()}
before=snapshot();result=subprocess.run([str(binary),'plan','--format','json','--sso-start-url',session['start_url'],'--sso-session-name',session['name'],'--test-root',str(root),'--test-endpoint',endpoint,'--state-dir',str(root/'state'),'--prefix','shared','--role','AWSReadOnlyAccess'],env=env,capture_output=True,text=True,timeout=20)
assert result.returncode==0,result.stderr
value=json.loads(result.stdout);names=[r['profile']['name'] for r in value['results']];assert len(names)==2 and len(set(names))==2;assert '111111111111' in names[0] and '222222222222' in names[1];assert before==snapshot() and not (root/'config').exists();server.shutdown()
print(json.dumps({'case':'P03','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'validation':'compiled_cli_same_name_account_plan','status':'PASS','names':names,'plan_zero_writes':True,'root':str(root)}))
