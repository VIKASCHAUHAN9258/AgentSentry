import pytest
pytest.importorskip('flask')
from api.app import create_app
from core.telemetry import TelemetryStore, init_db


def test_review_api_records_and_exposes_operator_decision(tmp_path):
    db=tmp_path/'review.db'; init_db(db)
    store=TelemetryStore('demo-code-reviewer',db_path=db)
    store.log_call('read_file',{'path':'benign_review.txt'},1,False,'Clean review notes')
    store.end_session()
    client=create_app({'TESTING':True,'DATABASE':str(db),'MODEL_DIR':str(tmp_path/'models')}).test_client()
    status=client.get(f'/api/sessions/{store.session_id}/review')
    assert status.status_code==200 and status.json['decision']=='unreviewed'
    missing=client.post(f'/api/sessions/{store.session_id}/review',json={'decision':'approved','reviewer':'op'})
    assert missing.status_code==400
    approved=client.post(f'/api/sessions/{store.session_id}/review',json={
        'decision':'approved','reviewer':'operator-1','note':'Inspected all evidence','confirm_reviewed':True,
    })
    assert approved.status_code==201
    status=client.get(f'/api/sessions/{store.session_id}/review')
    assert status.json['decision']=='approved' and status.json['evidence_current'] is True
    assert status.json['reviewer']=='operator-1'


def test_review_api_rejects_non_local_and_malformed_requests(tmp_path):
    db=tmp_path/'review.db'; init_db(db)
    store=TelemetryStore('demo-code-reviewer',db_path=db)
    store.log_call('read_file',{},1,False,'ok'); store.end_session()
    client=create_app({'TESTING':True,'DATABASE':str(db)}).test_client()
    response=client.post(f'/api/sessions/{store.session_id}/review',json={},environ_base={'REMOTE_ADDR':'192.0.2.4'})
    assert response.status_code==403
    response=client.post(f'/api/sessions/{store.session_id}/review',data='not-json',content_type='text/plain')
    assert response.status_code==415
