"""bindchain MVP 紅隊測試：五條合約逐條打。

依賴 canonlock：clone https://github.com/fango19961106-dotcom/canonlock 喺側邊
（../canonlock/canonlock.py），或者將 canonlock.py 抄落嚟呢個目錄。
"""
import os, sqlite3, time, pytest, sys
_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)
sys.path.insert(0, os.path.join(_here, "..", "canonlock"))
from canonlock import CanonLock, Policy
from bindchain import Identity, Chain, delegate, attest, verify_attestation, verify_delegation_chain
from bindchain_gate import BoundGate

DB = "test_bc.db"

@pytest.fixture()
def env():
    if os.path.exists(DB): os.remove(DB)
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE orders(id INTEGER PRIMARY KEY, customer_id INT, amount REAL, status TEXT, internal_note TEXT);
    INSERT INTO orders VALUES (1,1,1200.0,'pending','S1'),(2,2,350.0,'pending','S2');
    """)
    c.close()
    boss, bot, gid = Identity("boss"), Identity("analyst-bot"), Identity("gate")
    chain = Chain()
    gate = CanonLock(DB, Policy({
        "analyst-bot": {"orders": {"ops": ["UPDATE"], "writable_columns": ["status"], "require_where": True}}
    }))
    bg = BoundGate(gate, gid, chain)
    yield dict(boss=boss, bot=bot, gid=gid, chain=chain, bg=bg, gate=gate)
    if os.path.exists(DB): os.remove(DB)

def propose(env, sql="UPDATE orders SET status='paid' WHERE id=1"):
    r = env["bg"].propose("analyst-bot", env["boss"], sql)
    assert r.get("pending"), r
    return r["approval_id"]

def good_att(env, aid):
    deleg = delegate(env["boss"], env["bot"].pubkey_hex, scope={"table": "orders"})
    return attest(env["boss"], dict(canon_hash=env["bg"].pending[aid]["canon_hash"], approval_id=aid), [deleg])

# ---------- 正路 ----------
def test_happy_path(env):
    aid = propose(env)
    assert env["bg"].approve_with_attestation(aid, good_att(env, aid))["ok"]
    r = env["bg"].execute("analyst-bot", "UPDATE orders SET status='paid' WHERE id=1", aid)
    assert r["ok"] and r["affected"] == 1
    types = [e["obj"]["payload"]["type"] for e in env["chain"].entries]
    assert types == ["proposal", "attestation", "receipt"]
    ok, _ = env["bg"].verify_offline()
    assert ok

# ---------- 合約一：自簽自批 / 假簽名 ----------
def test_wrong_signer_rejected(env):
    aid = propose(env)
    mallory = Identity("mallory")
    deleg = delegate(env["boss"], env["bot"].pubkey_hex, scope={})
    att = attest(mallory, dict(canon_hash=env["bg"].pending[aid]["canon_hash"], approval_id=aid), [deleg])
    r = env["bg"].approve_with_attestation(aid, att)
    assert not r["ok"] and "chain root" in r["error"]

def test_tampered_signature_rejected(env):
    aid = propose(env)
    att = good_att(env, aid)
    att["payload"]["statement"]["canon_hash"] = "0" * 64  # 簽完再改內容
    r = env["bg"].approve_with_attestation(aid, att)
    assert not r["ok"] and "signature" in r["error"]

# ---------- 合約二：證明綁死語句 ----------
def test_attestation_for_other_statement_rejected(env):
    aid = propose(env, "UPDATE orders SET status='paid' WHERE id=1")
    aid2 = propose(env, "UPDATE orders SET status='paid' WHERE id=2")
    att = good_att(env, aid2)   # 批嘅係第二張單
    r = env["bg"].approve_with_attestation(aid, att)  # 攞嚟批第一張
    assert not r["ok"] and "mismatch" in r["error"]

# ---------- 合約三：delegation 鏈 ----------
def test_broken_chain_rejected(env):
    aid = propose(env)
    boss, bot = env["boss"], env["bot"]
    d1 = delegate(boss, bot.pubkey_hex, scope={})
    d2 = delegate(Identity("eve"), boss.pubkey_hex, scope={})  # 斷鏈：eve 唔係上一環
    att = attest(boss, dict(canon_hash=env["bg"].pending[aid]["canon_hash"], approval_id=aid), [d1, d2])
    r = env["bg"].approve_with_attestation(aid, att)
    assert not r["ok"] and "chain broken" in r["error"]

def test_expired_delegation_rejected(env):
    aid = propose(env)
    d = delegate(env["boss"], env["bot"].pubkey_hex, scope={}, ttl=-1)  # 即刻過期
    att = attest(env["boss"], dict(canon_hash=env["bg"].pending[aid]["canon_hash"], approval_id=aid), [d])
    r = env["bg"].approve_with_attestation(aid, att)
    assert not r["ok"] and "expired" in r["error"]

# ---------- 合約四：收據回鏈，包括 rollback ----------
def test_rollback_also_receipted(env):
    aid = propose(env, "UPDATE orders SET status='review' WHERE customer_id=1")
    assert env["bg"].approve_with_attestation(aid, good_att(env, aid))["ok"]
    db = sqlite3.connect(DB)
    for _ in range(50):
        db.execute("INSERT INTO orders(customer_id,amount,status) VALUES (1,10.0,'pending')")
    db.commit(); db.close()
    r = env["bg"].execute("analyst-bot", "UPDATE orders SET status='review' WHERE customer_id=1", aid)
    assert not r["ok"] and "rolled back" in r["error"]
    last = env["chain"].entries[-1]["obj"]["payload"]
    assert last["type"] == "receipt" and last["ok"] is False

# ---------- 合約五：鏈完整性 ----------
def test_chain_tamper_detected(env):
    aid = propose(env)
    env["bg"].approve_with_attestation(aid, good_att(env, aid))
    env["chain"].entries[0]["obj"]["payload"]["est_rows"] = 999
    ok, pos = env["chain"].verify()
    assert not ok and pos == 0

def test_chain_deletion_detected(env):
    aid = propose(env)
    env["bg"].approve_with_attestation(aid, good_att(env, aid))
    env["bg"].execute("analyst-bot", "UPDATE orders SET status='paid' WHERE id=1", aid)
    del env["chain"].entries[1]  # 刪走中間嘅 attestation
    ok, pos = env["chain"].verify()
    assert not ok

# ---------- 閘口本身嘅防線仍然喺度 ----------
def test_gate_still_denies_tautology(env):
    r = env["bg"].propose("analyst-bot", env["boss"], "UPDATE orders SET status='x' WHERE 1=1")
    assert not r.get("pending") and "tautological" in r["error"]

def test_gate_replay_still_blocked(env):
    aid = propose(env)
    env["bg"].approve_with_attestation(aid, good_att(env, aid))
    sql = "UPDATE orders SET status='paid' WHERE id=1"
    assert env["bg"].execute("analyst-bot", sql, aid)["ok"]
    assert "spent" in env["bg"].execute("analyst-bot", sql, aid)["error"]
