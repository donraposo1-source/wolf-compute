from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field
from hashlib import sha256
import json, time

class BaseReq(BaseModel):
    model_config = {'extra':'forbid'}
class CIFailureTriageReq(BaseReq):
    repository:str=Field(min_length=3); target:str=Field(min_length=1); expected_head:str|None=None; observed_head:str|None=None; workflow_status:str|None=None; failed_steps:list[str]=[]; external_error:str|None=None
class DependencyRiskAuditReq(BaseReq):
    repository:str=Field(min_length=3); head:str|None=None; dependencies:list[dict[str,Any]]=[]; vulnerabilities:list[dict[str,Any]]=[]; external_error:str|None=None
class PRReadinessReq(BaseReq):
    repository:str=Field(min_length=3); pr:int=Field(gt=0); expected_head:str=Field(min_length=7); observed_head:str|None=None; checks:list[dict[str,Any]]=[]; reviews:list[dict[str,Any]]=[]; mergeable:bool|None=None; external_error:str|None=None
class EvidencePackReq(BaseReq):
    mission_id:str=Field(min_length=1); target:str=Field(min_length=1); evidence_items:list[dict[str,Any]]; authority_allows_persist:bool=False; persist_requested:bool=False
class CheckpointPackagerReq(BaseReq):
    mission_id:str=Field(min_length=1); previous_checkpoint:str|None=None; observed_state:dict[str,Any]; verified_evidence:list[dict[str,Any]]; verifier_result:str; authority_envelope:dict[str,Any]

def _hash(obj:Any)->str:
    return sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()

def ci_failure_triage(request:CIFailureTriageReq):
    """Deterministically classify bounded CI failure evidence without writes or authority escalation."""
    unknown=[]
    if request.external_error:
        return {'SKILL':'WOLF_CI_FAILURE_TRIAGE','TARGET':request.target,'HEAD':request.observed_head,'STATUS':'UNKNOWN','FAILURE_CLASS':'EXTERNAL_TOOL_FAILURE','PRIMARY_EVIDENCE':[request.external_error],'DETERMINISTIC':True,'RETRYABLE':True,'AUTHORITY_REQUIRED':'NONE','NEXT_SAFE_ACTION':'RECONCILE_READ_ONLY','UNKNOWN_FIELDS':['workflow_status'],'MERGE_AUTHORITY':'NONE'}
    if not request.observed_head: unknown.append('observed_head')
    if not request.workflow_status: unknown.append('workflow_status')
    if request.expected_head and request.observed_head and request.expected_head!=request.observed_head:
        return {'SKILL':'WOLF_CI_FAILURE_TRIAGE','TARGET':request.target,'HEAD':request.observed_head,'STATUS':'BLOCKED','FAILURE_CLASS':'HEAD_MISMATCH','PRIMARY_EVIDENCE':[{'expected':request.expected_head,'observed':request.observed_head}],'DETERMINISTIC':True,'RETRYABLE':False,'AUTHORITY_REQUIRED':'NONE','NEXT_SAFE_ACTION':'RECONCILE_EXACT_HEAD','UNKNOWN_FIELDS':unknown,'MERGE_AUTHORITY':'NONE'}
    if unknown: status,fclass,next_action='UNKNOWN','INSUFFICIENT_EVIDENCE','FETCH_MISSING_READ_ONLY_EVIDENCE'
    elif request.workflow_status.lower() in {'success','completed_success','passed','pass'}: status,fclass,next_action='PASS','NONE','NO_ACTION'
    elif request.failed_steps: status,fclass,next_action='FAIL','DETERMINISTIC_STEP_FAILURE','INSPECT_FAILED_STEP_EVIDENCE'
    else: status,fclass,next_action='UNKNOWN','UNCLASSIFIED_WORKFLOW_STATE','RECONCILE_READ_ONLY'
    return {'SKILL':'WOLF_CI_FAILURE_TRIAGE','TARGET':request.target,'HEAD':request.observed_head,'STATUS':status,'FAILURE_CLASS':fclass,'PRIMARY_EVIDENCE':[{'workflow_status':request.workflow_status,'failed_steps':request.failed_steps}],'DETERMINISTIC':True,'RETRYABLE':status=='UNKNOWN','AUTHORITY_REQUIRED':'NONE','NEXT_SAFE_ACTION':next_action,'UNKNOWN_FIELDS':unknown,'MERGE_AUTHORITY':'NONE'}

def dependency_risk_audit(request:DependencyRiskAuditReq):
    """Normalize dependency and vulnerability evidence into a fail-closed audit envelope."""
    if request.external_error:
        return {'SKILL':'WOLF_DEPENDENCY_RISK_AUDIT','TARGET':request.repository,'HEAD':request.head,'DEPENDENCIES_CHECKED':len(request.dependencies),'VULNERABILITIES':[],'SEVERITY':'UNKNOWN','AFFECTED_COMPONENTS':[],'PRIMARY_EVIDENCE':[request.external_error],'UNKNOWN_FIELDS':['vulnerability_evidence'],'VERDICT':'UNKNOWN'}
    unknown=[]
    if not request.head: unknown.append('head')
    if not request.dependencies: unknown.append('dependencies')
    vulns=request.vulnerabilities or []
    affected=sorted({str(v.get('package') or v.get('component') or 'UNKNOWN') for v in vulns})
    severities=[str(v.get('severity','UNKNOWN')).upper() for v in vulns]
    rank={'UNKNOWN':0,'LOW':1,'MODERATE':2,'MEDIUM':2,'HIGH':3,'CRITICAL':4}
    severity=max(severities,key=lambda x:rank.get(x,0)) if severities else 'NONE'
    verdict='FAIL' if vulns else ('UNKNOWN' if unknown else 'PASS')
    return {'SKILL':'WOLF_DEPENDENCY_RISK_AUDIT','TARGET':request.repository,'HEAD':request.head,'DEPENDENCIES_CHECKED':len(request.dependencies),'VULNERABILITIES':vulns,'SEVERITY':severity,'AFFECTED_COMPONENTS':affected,'PRIMARY_EVIDENCE':[{'dependencies':len(request.dependencies),'vulnerability_count':len(vulns)}],'UNKNOWN_FIELDS':unknown,'VERDICT':verdict}

def pr_readiness(request:PRReadinessReq):
    """Evaluate exact-head PR readiness from deterministic evidence; never grants merge authority."""
    unknown=[]
    if request.external_error: unknown.append('external_evidence')
    if not request.observed_head: unknown.append('observed_head')
    if request.observed_head and request.observed_head!=request.expected_head: readiness,head_match='BLOCKED',False
    else:
        head_match=None if not request.observed_head else True
        conclusions=[str(c.get('conclusion') or c.get('status') or '').lower() for c in request.checks]
        bad={'failure','failed','cancelled','timed_out','action_required','error'}; pending={'queued','in_progress','pending','requested','waiting'}
        if any(c in bad for c in conclusions): readiness='BLOCKED'
        elif any(c in pending or c=='' for c in conclusions) or not request.checks or request.mergeable is None or unknown: readiness='UNKNOWN'
        elif request.mergeable is False: readiness='BLOCKED'
        else: readiness='READY'
    return {'SKILL':'WOLF_PR_READINESS','PR':request.pr,'EXPECTED_HEAD':request.expected_head,'OBSERVED_HEAD':request.observed_head,'HEAD_MATCH':head_match,'CHECKS':request.checks,'REVIEWS':request.reviews,'MERGEABILITY':request.mergeable,'PRIMARY_EVIDENCE':[{'repository':request.repository}],'UNKNOWN_FIELDS':unknown,'READINESS':readiness,'MERGE_AUTHORITY':'NONE'}

def evidence_pack(request:EvidencePackReq):
    """Create a deterministic Wolf evidence package; persistence is denied unless explicitly requested and authorized."""
    now=int(time.time()); unknown=[]; head=tree=None; run_ids=[]; checks=[]; artifacts=[]; hashes=[]; sources=[]; identifiers=[]
    for item in request.evidence_items:
        if item.get('source'): sources.append(item.get('source'))
        if item.get('id'): identifiers.append(item.get('id'))
        head=head or item.get('head'); tree=tree or item.get('tree')
        if item.get('run_id') is not None: run_ids.append(item.get('run_id'))
        if item.get('check_result') is not None: checks.append(item.get('check_result'))
        if item.get('artifact') is not None: artifacts.append(item.get('artifact'))
        if item.get('hash') is not None: hashes.append(item.get('hash'))
    if not request.evidence_items: unknown.append('evidence_items')
    persist_allowed=request.persist_requested and request.authority_allows_persist
    if request.persist_requested and not request.authority_allows_persist: unknown.append('persistence_authority')
    payload={'MISSION_ID':request.mission_id,'TARGET':request.target,'TIMESTAMP':now,'SOURCE':sources,'IDENTIFIERS':identifiers,'HEAD':head,'TREE':tree,'RUN_IDS':run_ids,'CHECK_RESULTS':checks,'ARTIFACT_REFERENCES':artifacts,'HASHES':hashes,'UNKNOWN_FIELDS':unknown,'PROVENANCE':{'input_sha256':_hash(request.evidence_items)},'PERSIST_REQUESTED':request.persist_requested,'PERSIST_AUTHORIZED':persist_allowed,'EXTERNAL_MUTATION_PERFORMED':False}
    payload['PACK_SHA256']=_hash(payload); return payload

def durable_checkpoint_packager(request:CheckpointPackagerReq):
    """Package, but never promote, a durable checkpoint candidate under an explicit authority envelope."""
    verified=str(request.verifier_result).upper() in {'PASS','VERIFIED','TRUE'}; auth=bool(request.authority_envelope.get('checkpoint_package',False)); unknown=[]
    if not verified: unknown.append('verified_state')
    if not auth: unknown.append('checkpoint_package_authority')
    completed=request.observed_state.get('completed_edge') if verified else None; first_unfinished=request.observed_state.get('first_unfinished_edge'); next_candidate=request.observed_state.get('next_ready_candidate') if verified and auth else None
    guard=_hash({'mission_id':request.mission_id,'previous':request.previous_checkpoint,'state':request.observed_state,'evidence':request.verified_evidence})
    return {'SKILL':'WOLF_DURABLE_CHECKPOINT_PACKAGER','MISSION_ID':request.mission_id,'PREVIOUS_CHECKPOINT':request.previous_checkpoint,'OBSERVED_STATE':request.observed_state,'VERIFICATION':request.verifier_result,'COMPLETED_EDGE':completed,'FIRST_UNFINISHED_EDGE':first_unfinished,'NEXT_READY_CANDIDATE':next_candidate,'DUPLICATE_GUARD':guard,'PROVENANCE':{'evidence_sha256':_hash(request.verified_evidence)},'UNKNOWN_FIELDS':unknown,'CHECKPOINT_PROMOTED':False,'NEXT_READY_GRANTED':False,'MERGE_AUTHORITY':'NONE','DEPLOYMENT_AUTHORITY':'NONE'}

for _m in [CIFailureTriageReq,DependencyRiskAuditReq,PRReadinessReq,EvidencePackReq,CheckpointPackagerReq]:
    _m.model_rebuild()

SKILLS={'WOLF_CI_FAILURE_TRIAGE':(CIFailureTriageReq,ci_failure_triage),'WOLF_DEPENDENCY_RISK_AUDIT':(DependencyRiskAuditReq,dependency_risk_audit),'WOLF_PR_READINESS':(PRReadinessReq,pr_readiness),'WOLF_EVIDENCE_PACK':(EvidencePackReq,evidence_pack),'WOLF_DURABLE_CHECKPOINT_PACKAGER':(CheckpointPackagerReq,durable_checkpoint_packager)}
if __name__=='__main__': print(json.dumps({'toolkit':'WOLF','skills':list(SKILLS),'version':'1.0.0'},indent=2))
