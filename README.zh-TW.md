# onprem-agent-gate

[English](README.md)

AI 代理程式碰這個場域的唯一一道門。代理程式拿到的是一份工具清單，每個工具是某一台資產上的一條固定命令。每一次呼叫都要寫明一張變更單（[onprem-changes](https://github.com/ivanusto/onprem-changes)，Day 26），閘道只放到那張單、它的窗、以及人允許的程度。每一個決定都是一筆雜湊鏈結的稽核紀錄加一行 journal，進到場域其他東西都在的那個 WORM 封存（Day 21、27）。

```
代理程式（任何 MCP 用戶端） --ssh 強制命令--> 收集端的 gate-mcp
                                                |  判定：單子、agent:、assets、status、
                                                |        窗、begin 標記、等級、核准
                                                |  稽核：audit.jsonl（sha256 鏈）加 journal 一行
                                                v
                                          ssh gate@目標 -- <固定 argv>
```

| 等級 | 意思 | 要有什麼 |
|---|---|---|
| L1 | 唯讀（狀態、journal、有上限的查詢） | 單子是 `approved`、`scheduled` 或 `in_progress`，`agent:` 寫了這個代理程式，`assets:` 列了這台資產 |
| L2 | 可逆的變更（重啟服務） | L1 加 `in_progress`、現在在窗內、begin 標記在檔（`change-mark.sh begin` 跑過而 `end` 還沒） |
| L3 | 不可逆（重開機） | L2 加一位人的核准，單次使用、10 分鐘有效、綁定這一次呼叫的內容（`sudo -u agent-gate gatectl approve <seq>`） |

`STOP` 檔存在時全部拒絕（`gatectl stop` / `resume`）。工具不在清單、參數不符正規表達式、單子沒寫這個代理程式或這台資產，一律 DENY，理由寫進稽核也回給模型。

## 目錄

| 路徑 | 用途 |
|---|---|
| `gate/core.py` | 判定、執行（本機或 `ssh 目標 -- argv`）、雜湊鏈、核准 |
| `gate/mcp_server.py`、`bin/gate-mcp` | stdio 的 MCP：`initialize`、`tools/list`、`tools/call`、`ping` |
| `bin/gatectl` | 操作者這一側：`call`、`tools`、`pending`、`approve`、`stop`、`resume`、`verify [--vl]`、`tail`、`textfile` |
| `gate/textfile.py` | 給 node_exporter 的 `agent-gate.prom` |
| `tools.json` | 這個場域的工具：id、等級、資產、帶 `{參數}` 的 argv、每個參數一條正規表達式 |
| `config.json.example` | principal、路徑（單子的 clone、change-mark 的狀態目錄、稽核檔、核准目錄、STOP）、ssh 命令、資產到目標的對應 |
| `prometheus/agent.yml`、`tests/rules_agent_test.yml` | 五條規則，複本，正本在 onprem-metrics |
| `collector.cron` | 每 5 分鐘的 textfile |
| `docs/targets.md` | 每台目標上的 `gate` 使用者：`restrict,from=` 的金鑰行，只涵蓋那幾條 argv 的 sudoers |
| `docs/mcp-clients.md` | 每個代理程式一把金鑰、一條強制命令，Claude Code 與其他用戶端的接法 |
| `docs/iso27001.md` | 每一塊對到 Annex A 哪一條控制措施，以及它不做什麼 |
| `tests/` | `unittest`（政策、核准、鏈、textfile、MCP）、`smoke-gatectl.sh`、`smoke-mcp.sh`、`promtool test rules` |

## 怎麼跑

```sh
# 收集端，一次：使用者、目錄、金鑰、設定、clone 的讀取權（docs/targets.md）
sudo install -m 0644 tools.json /etc/onprem-agent-gate/tools.json
sudo install -m 0644 config.json.example /etc/onprem-agent-gate/config.json && sudoedit /etc/onprem-agent-gate/config.json

# 一張寫了 agent: 的單子，有窗，由操作者打開
sudo -u metrics /opt/onprem-changes/scripts/change-mark.sh begin CR-2026-0015

# 代理程式看到的東西，從 shell 試
sudo -u agent-gate gatectl call CR-2026-0015 qdevice.service_status unit=corosync-qnetd.service   # L1，ALLOW
sudo -u agent-gate gatectl call CR-2026-0015 qdevice.restart_service unit=corosync-qnetd.service  # L2，窗內 ALLOW
sudo -u agent-gate gatectl call CR-2026-0015 qdevice.reboot                                       # L3，PENDING，request 7
sudo -u agent-gate gatectl approve 7                                                              # 由單子的 implementer 或 approver
sudo -u agent-gate gatectl call CR-2026-0015 qdevice.reboot --approval 7                          # ALLOW，用過即失效

# 代理程式本身：工作站上的 Claude Code，一把金鑰，收集端上一條強制命令
claude mcp add --transport stdio onprem-gate -- ssh -i ~/.ssh/id_agent_ops agent-gate@collector

# 證據
sudo -u agent-gate gatectl tail 20
sudo -u agent-gate gatectl verify --vl http://127.0.0.1:9428      # 鏈，加上每一筆的雜湊前綴都在 VictoriaLogs 裡
sudo -u metrics /opt/onprem-logs/audit/audit-report.py --since <窗開始>   # 閘道的行被歸到那張單
```

## 稽核紀錄

```json
{"seq":12,"ts":"2026-10-13T12:31:07Z","prev":"<seq 11 的 hash>","principal":"agent:ops","operator":"ivan",
 "cr":"CR-2026-0015","tool":"qdevice.restart_service","level":"L2","params":{"unit":"corosync-qnetd.service"},
 "decision":"ALLOW","reason":"L2 inside an open window with the begin mark",
 "action_hash":"<principal+cr+tool+params 的 sha256>","approval":null,
 "exec":{"rc":0,"duration_s":1.42,"stdout_sha256":"...","stdout_bytes":0,"timed_out":false},
 "hash":"<prev 加正規化紀錄的 sha256>"}
```

同一刻的 journal 行，tag `agent-gate`：

```
seq=12 principal=agent:ops operator=ivan cr=CR-2026-0015 tool=qdevice.restart_service level=L2 decision=ALLOW rc=0 hash=3f9c2a71b0e4d5c6
```

檔案是一台主機上的檔案。journal 行幾秒內上傳，隔天早上進 WORM，`gatectl verify --vl` 把每一筆對上它的那一行。改檔案會斷鏈，換檔案會讓 WORM 裡有行而檔案裡沒有紀錄。

## 不在範圍內

用哪個模型、哪個 runtime、什麼提示詞。閘道看到的是一個帶 `cr` 的工具呼叫，它不管是誰組出來的。人用 `gatectl call` 得到一樣的待遇，測試也是這樣做的。邊界見 [docs/iso27001.md](docs/iso27001.md)。

## 來歷

「工單即授權」、動作分級、單次核准、雜湊鏈稽核，來自 2026 年 8 月黑客松的 TrustedOps 設計（Governed Agent Trust Layer）。那個設計把控制平面與執行端分開，核准走網頁儀表板。這個 repo 把兩者都收在收集端上，工單換成 git 裡的變更單，儀表板換成 sudo，因為這個場域本來就只對這些東西有稽核軌跡。

## 授權

Apache-2.0
