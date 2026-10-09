"""bindchain 端到端 demo：人批 SQL → 閘口驗證執行 → 收據回鏈 → 離線驗證。

依賴 canonlock：clone https://github.com/fango19961106-dotcom/canonlock 喺側邊（../canonlock/）。
"""
import sqlite3, os, sys
_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)
sys.path.insert(0, os.path.join(_here, "..", "canonlock"))
from canonlock import CanonLock, Policy
from bindchain import Identity, Chain, delegate, attest
from bindchain_gate import BoundGate

DB = "e2e.db"
if os.path.exists(DB): os.remove(DB)
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE orders(id INTEGER PRIMARY KEY, customer_id INT, amount REAL, status TEXT, internal_note TEXT);
INSERT INTO orders VALUES (1,1,1200.0,'pending','S1'),(2,2,350.0,'pending','S2'),(3,1,800.0,'paid','S3');
""")
c.close()

# 三個身份：老闆（人）、分析 agent、閘口自己
boss = Identity("boss")
bot_key = Identity("analyst-bot")
gate_id = Identity("canonlock-gate")
chain = Chain()

gate = CanonLock(DB, Policy({
    "analyst-bot": {"orders": {"ops": ["UPDATE"], "writable_columns": ["status"], "require_where": True}}
}))
bg = BoundGate(gate, gate_id, chain)

# 老闆授權 agent 喺呢個 scope 行事
deleg = delegate(boss, bot_key.pubkey_hex, scope={"table": "orders", "columns": ["status"]})

print("=" * 72)
print("1. Agent 提出寫入（經閘口 AST 檢查 + 行數估算）")
r = bg.propose("analyst-bot", boss, "UPDATE orders SET status='paid' WHERE id=2")
aid = r["approval_id"]
print(f"   開單 {aid}｜canonical: {r['canonical']}｜est_rows: {r['est_rows']}")

print("\n2. 老闆簽 attestation 批核（證明綁死 canonical hash + approval_id + 帶 delegation 鏈）")
att = attest(boss, dict(canon_hash=bg.pending[aid]["canon_hash"], approval_id=aid), [deleg])
r = bg.approve_with_attestation(aid, att)
print(f"   閘口驗證 attestation: {r}")

print("\n3. Agent 執行（閘口兌換 token、行數綁定、結果簽收據回鏈）")
r = bg.execute("analyst-bot", "update orders set status='paid' where id=2", aid)
print(f"   執行: {r}")
print("   DB:", sqlite3.connect(DB).execute("SELECT id,status FROM orders ORDER BY id").fetchall())

print("\n4. 鏈上而家有：proposal → attestation → receipt")
for e in chain.entries:
    p = e["obj"]["payload"]
    print(f"   [{p['type']:>11}] signer={e['obj']['signer'][:12]}… chain={e['chain_hash'][:12]}…")

ok, pos = bg.verify_offline()
print(f"\n5. 離線驗證鏈完整性: {'✅ 通過' if ok else f'❌ 斷於 {pos}'}")
print(f"   鏈尾（外部錨點要錨嘅就係佢）: {chain.tip[:32]}…")
