"""bindchain-core — attestation 鏈 × 執法點 整合層（MVP v0.1）

五條合約：
 1. 鏈不可替換：執法點只接受外部鏈簽發嘅證明；自簽自批即拒
 2. 證明綁死語句：attestation 內含 canonical SQL hash；講 A 執行 B 即拒
 3. delegation 鏈唔准斷：人 → agent（→ sub-agent）每環簽名，斷一環即拒
 4. 執行後回寫收據：結果（affected / rolled-back）簽成 receipt 上鏈
 5. 離線可驗證：鏈檔案 + 公鑰即可驗證全部四件事

格式係最小自洽集，對齊 APS（draft-pidlisnyi-aps-01）嘅 delegation/receipt 語義；
轉接真 APS 格式只需換 serialize/deserialize 一層。
"""
import hashlib, json, time, uuid
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

# ---------- 序列化（JCS 風格：排序 key、UTF-8、無空白） ----------
def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ---------- 身份 ----------
class Identity:
    """Ed25519 身份。人同 agent 都係 Identity；分別只在於邊個授權邊個。"""
    def __init__(self, name: str, seed: bytes = None):
        self.name = name
        self.sk = SigningKey(seed) if seed else SigningKey.generate()
        self.vk = self.sk.verify_key

    @property
    def pubkey_hex(self) -> str:
        return self.vk.encode().hex()

    def sign(self, payload: dict) -> dict:
        body = canonical_json(payload)
        sig = self.sk.sign(body).signature.hex()
        return dict(payload=payload, signer=self.pubkey_hex, sig=sig)

    @staticmethod
    def verify(signed: dict) -> bool:
        try:
            VerifyKey(bytes.fromhex(signed["signer"])).verify(
                canonical_json(signed["payload"]), bytes.fromhex(signed["sig"]))
            return True
        except (BadSignatureError, KeyError, ValueError):
            return False

# ---------- Delegation（合約三） ----------
def delegate(issuer: Identity, delegatee_pubkey: str, scope: dict, ttl=3600) -> dict:
    """issuer 授權 delegatee 喺 scope 入面行事。scope 例：{"canon_hash": ..., "max_rows": N}"""
    payload = dict(type="delegation", iss=issuer.pubkey_hex, sub=delegatee_pubkey,
                   scope=scope, exp=time.time() + ttl, nonce=uuid.uuid4().hex[:12])
    return issuer.sign(payload)

def verify_delegation_chain(chain: list, root_human_pubkey: str) -> (bool, str):
    """逐環驗簽名 + 鏈式 iss/sub 銜接 + 未過期。根必須係人（root_human_pubkey）。"""
    if not chain:
        return False, "empty delegation chain"
    if chain[0]["payload"]["iss"] != root_human_pubkey:
        return False, "chain root is not the human"
    prev_sub = root_human_pubkey
    for i, link in enumerate(chain):
        if not Identity.verify(link):
            return False, f"link {i}: bad signature"
        p = link["payload"]
        if p.get("type") != "delegation":
            return False, f"link {i}: not a delegation"
        if p["iss"] != prev_sub:
            return False, f"link {i}: chain broken (iss != previous sub)"
        if time.time() > p["exp"]:
            return False, f"link {i}: delegation expired"
        prev_sub = p["sub"]
    return True, None

# ---------- Attestation（合約一、二） ----------
def attest(approver: Identity, statement: dict, delegation_chain: list) -> dict:
    """approver（鏈根嘅人）對一個 statement 簽批核證明。
    statement 例：{"canon_hash": ..., "approval_id": ..., "max_rows": N}"""
    payload = dict(type="attestation", statement=statement,
                   chain=delegation_chain, ts=time.time(), nonce=uuid.uuid4().hex[:12])
    return approver.sign(payload)

def verify_attestation(att: dict, expected_human_pubkey: str, expect: dict) -> (bool, str):
    """合約一＋二＋三：簽名真、人係鏈根、鏈唔斷、內容同執法點期望一致。"""
    if not Identity.verify(att):
        return False, "attestation signature invalid"
    p = att["payload"]
    if p.get("type") != "attestation":
        return False, "not an attestation"
    if att["signer"] != expected_human_pubkey:
        return False, "attestation not signed by the chain root human"
    ok, why = verify_delegation_chain(p["chain"], expected_human_pubkey)
    if not ok:
        return False, f"delegation chain: {why}"
    st = p["statement"]
    for k, v in expect.items():          # 執法點話事：hash、approval_id 必須一致
        if st.get(k) != v:
            return False, f"statement.{k} mismatch: approved {st.get(k)} != expected {v}"
    return True, None

# ---------- 鏈（合約四、五） ----------
class Chain:
    """append-only hash-chain。每條 entry 係一份簽名物件 + 鏈 hash。"""
    def __init__(self):
        self.entries = []

    def append(self, signed_obj: dict) -> dict:
        if not Identity.verify(signed_obj):
            raise ValueError("refusing to append object with bad signature")
        prev = self.entries[-1]["chain_hash"] if self.entries else "0" * 64
        entry = dict(obj=signed_obj, prev=prev)
        entry["chain_hash"] = sha256_hex(canonical_json(entry))
        self.entries.append(entry)
        return entry

    def verify(self) -> (bool, object):
        prev = "0" * 64
        for i, e in enumerate(self.entries):
            if e["prev"] != prev:
                return False, i
            if not Identity.verify(e["obj"]):
                return False, i
            if e["chain_hash"] != sha256_hex(canonical_json(dict(obj=e["obj"], prev=prev))):
                return False, i
            prev = e["chain_hash"]
        return True, None

    @property
    def tip(self) -> str:
        """鏈尾 hash——外部錨點就係錨呢個（RFC 3161 / webhook / 對方系統）。"""
        return self.entries[-1]["chain_hash"] if self.entries else "0" * 64
