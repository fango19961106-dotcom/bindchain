"""bindchain-adapter — 將 attestation 鏈接上 canonlock 閘口。

canonlock 本體唔改（佢係封存嘅參考實現）；adapter 提供：
  propose(agent, human_identity, sql)      — 開單，同時喺鏈上留 proposal attestation
  approve_with_attestation(aid, att, ...)  — 合約一至三：外部簽名證明先可以批
  execute(agent, sql, aid)                 — 執行；結果簽成 receipt 回鏈（合約四）
"""
import sys, time
from bindchain import Identity, Chain, verify_attestation

class BoundGate:
    def __init__(self, gate, gate_identity: Identity, chain: Chain):
        self.gate = gate            # canonlock.CanonLock
        self.gate_id = gate_identity
        self.chain = chain
        self.pending = {}           # aid -> dict(canon_hash, human_pubkey, est_rows)
        self.receipts = {}          # aid -> receipt entry

    def propose(self, agent: str, human: Identity, sql: str):
        r = self.gate.propose_write(agent, human.name, sql)
        if not r.get("pending"):
            return r
        self.pending[r["approval_id"]] = dict(
            canon_hash=self._hash_of(r["canonical"]),
            canonical=r["canonical"],
            human_pubkey=human.pubkey_hex, est_rows=r["est_rows"])
        # 開單都上鏈——審計由開單一刻開始
        self.chain.append(self.gate_id.sign(dict(
            type="proposal", approval_id=r["approval_id"],
            canon_hash=self.pending[r["approval_id"]]["canon_hash"],
            est_rows=r["est_rows"], ts=time.time())))
        return r

    @staticmethod
    def _hash_of(canon: str) -> str:
        import hashlib
        return hashlib.sha256(canon.encode()).hexdigest()

    def approve_with_attestation(self, aid: str, att: dict):
        """合約一＋二＋三：簽名真、批核人係鏈根、delegation 鏈唔斷、hash 綁死呢張單。"""
        p = self.pending.get(aid)
        if not p:
            return {"ok": False, "error": "unknown or already-settled approval id"}
        ok, why = verify_attestation(att, p["human_pubkey"], expect={
            "canon_hash": p["canon_hash"], "approval_id": aid})
        if not ok:
            self.gate._log("?", p["canonical"], "deny", f"attestation rejected: {why}", aid)
            return {"ok": False, "error": f"DENIED: attestation rejected: {why}"}
        # attestation 合法 → 標記 canonlock 張單做 approved（由密碼學頂替記名批核）
        rec = self.gate.approvals.store[aid]
        rec["status"] = "approved"
        rec["approved_by"] = att["signer"][:16] + "…(sig)"
        self.chain.append(att)      # 批核證明上鏈
        return {"ok": True}

    def execute(self, agent: str, sql: str, aid: str):
        r = self.gate.execute(agent, sql, aid)
        # 合約四：無論成功、rollback、定 replay 被擋，都簽 receipt 回鏈
        info = self.pending.pop(aid, None) or self.receipts.get(aid)
        canon_hash = info["canon_hash"] if info and "canon_hash" in info else self._hash_of(
            self.gate.approvals.store.get(aid, {}).get("canon", sql))
        entry = self.chain.append(self.gate_id.sign(dict(
            type="receipt", approval_id=aid, canon_hash=canon_hash,
            ok=bool(r.get("ok")), affected=r.get("affected", 0),
            error=r.get("error"), ts=time.time())))
        self.receipts[aid] = dict(canon_hash=canon_hash, entry=entry)
        return r

    def verify_offline(self):
        """合約五：鏈完整性。答「邊個批、批咩、執行咗未、改咗幾多行」靠鏈上 entries。"""
        return self.chain.verify()
