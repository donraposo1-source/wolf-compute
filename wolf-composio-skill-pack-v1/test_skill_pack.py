import importlib.util, json
p='/home/user/wolf-skill-pack/wolf_composio_skill_pack_v1.py'
s=importlib.util.spec_from_file_location('w',p); w=importlib.util.module_from_spec(s); s.loader.exec_module(w)
results=[]

def rec(name,ok,detail=None): results.append({'test':name,'pass':bool(ok),'detail':detail})

for cls,name in [(w.CIFailureTriageReq,'ci'),(w.DependencyRiskAuditReq,'dep'),(w.PRReadinessReq,'pr'),(w.EvidencePackReq,'ev'),(w.CheckpointPackagerReq,'cp')]:
    try: cls.model_json_schema(); rec(f'schema_{name}',True)
    except Exception as e: rec(f'schema_{name}',False,str(e))
try:
    w.CIFailureTriageReq(repository='x',target='t')
    rec('malformed_rejected',False)
except Exception: rec('malformed_rejected',True)
r=w.ci_failure_triage(w.CIFailureTriageReq(repository='o/r',target='run1',expected_head='abc1234',observed_head='abc1234',workflow_status='success')); rec('ci_happy',r['STATUS']=='PASS' and r['MERGE_AUTHORITY']=='NONE',r)
r=w.ci_failure_triage(w.CIFailureTriageReq(repository='o/r',target='run1')); rec('ci_missing_unknown',r['STATUS']=='UNKNOWN',r)
r=w.ci_failure_triage(w.CIFailureTriageReq(repository='o/r',target='run1',expected_head='abc1234',observed_head='def5678',workflow_status='success')); rec('ci_wrong_head_blocked',r['STATUS']=='BLOCKED',r)
r=w.ci_failure_triage(w.CIFailureTriageReq(repository='o/r',target='run1',external_error='timeout')); rec('ci_external_failure_unknown',r['STATUS']=='UNKNOWN',r)
r=w.dependency_risk_audit(w.DependencyRiskAuditReq(repository='o/r',head='abc1234',dependencies=[{'name':'a','version':'1'}],vulnerabilities=[])); rec('dep_happy_pass',r['VERDICT']=='PASS',r)
r=w.dependency_risk_audit(w.DependencyRiskAuditReq(repository='o/r')); rec('dep_missing_unknown',r['VERDICT']=='UNKNOWN',r)
r=w.dependency_risk_audit(w.DependencyRiskAuditReq(repository='o/r',head='abc1234',dependencies=[{'name':'a'}],vulnerabilities=[{'package':'a','severity':'HIGH'}])); rec('dep_vuln_fail',r['VERDICT']=='FAIL' and r['SEVERITY']=='HIGH',r)
r=w.pr_readiness(w.PRReadinessReq(repository='o/r',pr=1,expected_head='abc1234',observed_head='abc1234',checks=[{'conclusion':'success'}],reviews=[{'state':'approved'}],mergeable=True)); rec('pr_ready',r['READINESS']=='READY' and r['MERGE_AUTHORITY']=='NONE',r)
r=w.pr_readiness(w.PRReadinessReq(repository='o/r',pr=1,expected_head='abc1234',observed_head='def5678',checks=[{'conclusion':'success'}],mergeable=True)); rec('pr_wrong_head_blocked',r['READINESS']=='BLOCKED' and r['MERGE_AUTHORITY']=='NONE',r)
r=w.pr_readiness(w.PRReadinessReq(repository='o/r',pr=1,expected_head='abc1234')); rec('pr_missing_unknown',r['READINESS']=='UNKNOWN',r)
r=w.evidence_pack(w.EvidencePackReq(mission_id='m1',target='t',evidence_items=[{'source':'x','head':'abc'}],persist_requested=True,authority_allows_persist=False)); rec('evidence_authority_bypass_fail_closed',r['PERSIST_AUTHORIZED'] is False and r['EXTERNAL_MUTATION_PERFORMED'] is False and 'persistence_authority' in r['UNKNOWN_FIELDS'],r)
r2=w.evidence_pack(w.EvidencePackReq(mission_id='m1',target='t',evidence_items=[{'source':'x','head':'abc'}],persist_requested=False,authority_allows_persist=False)); rec('evidence_no_hidden_write',r2['EXTERNAL_MUTATION_PERFORMED'] is False,r2)
req=w.CheckpointPackagerReq(mission_id='m1',previous_checkpoint='c0',observed_state={'completed_edge':'e1','first_unfinished_edge':'e2','next_ready_candidate':'e2'},verified_evidence=[{'x':1}],verifier_result='PASS',authority_envelope={'checkpoint_package':True})
a=w.durable_checkpoint_packager(req); b=w.durable_checkpoint_packager(req); rec('checkpoint_package_no_promotion',a['CHECKPOINT_PROMOTED'] is False and a['NEXT_READY_GRANTED'] is False,a); rec('checkpoint_replay_guard_stable',a['DUPLICATE_GUARD']==b['DUPLICATE_GUARD'],a['DUPLICATE_GUARD'])
r=w.durable_checkpoint_packager(w.CheckpointPackagerReq(mission_id='m2',observed_state={'next_ready_candidate':'e2'},verified_evidence=[],verifier_result='PASS',authority_envelope={})); rec('checkpoint_authority_bypass_fail_closed',r['NEXT_READY_CANDIDATE'] is None and r['NEXT_READY_GRANTED'] is False,r)
failed=[x for x in results if not x['pass']]
print(json.dumps({'total':len(results),'passed':len(results)-len(failed),'failed':len(failed),'results':results},indent=2))
raise SystemExit(1 if failed else 0)
