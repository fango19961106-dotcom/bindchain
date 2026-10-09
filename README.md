# bindchain

**Attestation 鏈 × SQL 寫入閘口——令「邊個授權」嘅密碼學證明有牙。**

Attestation 鏈（APS、Signet）證明「係邊個」；寫入閘口（[canonlock](https://github.com/fango19961106-dotcom/canonlock)、pgwarden）管住「做乜」。**兩者之間嘅接駁冇人做——呢個 repo 就係嗰截接駁。**

## 五條合約

1. **鏈不可替換**：閘口只接受外部鏈簽發嘅批核證明，自簽自批即拒
2. **證明綁死語句**：attestation 內含 canonical SQL hash + approval_id；批 A 執行 B 即拒
3. **delegation 鏈唔准斷**：人 → agent 每環 Ed25519 簽名，斷一環、過期、根唔係人——即拒
4. **執行後回寫收據**：成功、rollback、replay 被擋，全部簽成 receipt 上鏈
5. **離線可驗證**：鏈檔案 + 公鑰即可驗證「邊個批、批咩、執行咗未、改咗幾多行」

```bash
pip install -r requirements.txt
git clone https://github.com/fango19961106-dotcom/canonlock ../canonlock  # 閘口依賴
python3 demo.py       # 端到端：開單 → 簽批 → 執行 → 收據 → 離線驗鏈
pytest -v             # 11 個測試（紅隊攻擊 + 正路 + 閘口防線回歸）
```

## 端到端流程

```
人（Ed25519）── 簽 delegation ──► Agent（持鏈行事）
Agent ──propose──► canonlock 閘口（AST fail-closed + 行數估算）
人 ──簽 attestation（綁 canon_hash + approval_id + delegation 鏈）──► 閘口驗證
閘口 ──執行（行數綁定、rollback 保護）──► receipt 回鏈
任何人 ──鏈檔案 + 公鑰──► 離線驗證全過程
```

## 定位聲明（誠實版）

- **唔係又一條鏈**：鏈本體我哋核實過，Signet/APS/IETF draft-sharif 已經做晒——所以我哋唔做鏈，做鏈嘅落地
- **唔係又一個閘口**：canonlock 係我哋自己嘅參考實現；production 用 pgwarden
- **係兩者之間嘅膠水**：格式層對齊 APS（draft-pidlisnyi-aps-01）語義，接真 APS 只需換序列化層

## 紅隊覆蓋（test_bindchain.py）

冒名簽名｜簽後改內容｜批 A 單攞嚟批 B 單｜delegation 斷鏈｜delegation 過期｜rollback 都回鏈｜鏈篡改檢出｜鏈中間刪除檢出｜閘口恒真拒絕｜token replay

## License

MIT
