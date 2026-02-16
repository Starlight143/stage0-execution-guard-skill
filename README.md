# Stage0 Execution Guard Skill

## 這個 skill 是做什麼的

Stage0 Execution Guard Skill 是一個執行守門員（execution gate）。它的唯一職責是：在 AI agent 執行任何行為之前，判斷該執行是否被允許。這是一個強制性的安全機制，不是可選功能。agent 必須先通過這個 guard 的檢查，才能繼續執行。如果 guard 阻擋了執行，agent 就無法繼續——無論 agent 的 prompt 如何設計。

## 為什麼只靠 prompt 無法阻止執行

Prompt 是指令，不是約束。LLM 可以理解「不要做某事」，但無法被強制遵守。當 model 產生幻覺、被誤導、或遇到 edge case 時，它可能會忽略或繞過 prompt 中的限制。更重要的是，prompt 無法控制執行層——它只能影響 model 的輸出。如果 model 決定要執行某個危險操作，prompt 無法在物理上阻止它。只有 code 可以做到這一點。這個 skill 就是一道 code 層面的強制關卡。

## 這個 execution guard 如何阻擋執行

Guard 透過「fail closed」原則運作：預設拒絕，只有明確授權才放行。當 agent 準備執行時，它必須先向 guard 提交執行意圖（execution intent），包含：目標（goal）、預計使用的工具（tools）、可能的副作用（side_effects）。Guard 將這些資訊送往 Stage0 API 進行授權檢查。Stage0 會返回三種結果之一：

- **ALLOW**：執行被允許，guard 返回成功，agent 繼續執行
- **DENY**：執行被拒絕，guard 拋出異常，agent 無法繼續
- **DEFER**：需要更多資訊，guard 拋出異常並附上澄清問題

關鍵點：只要 verdict 不是 ALLOW，執行就會被阻擋。沒有中間狀態，沒有「試試看」。如果 API key 未設定、無效、或 Stage0 服務不可用，執行同樣會被阻擋。

## 設定方式

1. 前往 https://signalpulse.org 註冊帳號
2. 在控制台取得 API Key
3. 設定環境變數：

```bash
export STAGE0_API_KEY=your-api-key-here
```

或在 Python 中直接指定：

```python
from stage0_execution_guard import Stage0Client, ExecutionGuard

client = Stage0Client(api_key="your-api-key-here")
guard = ExecutionGuard(client=client)
```

## 最小整合範例

```python
from stage0_execution_guard import ExecutionIntent, must_allow

# 定義執行意圖
intent = ExecutionIntent(
    goal="Read and summarize the weekly sales report",
    tools=["filesystem", "llm"],
    side_effects=[],  # 只讀取，無副作用
)

# 必須通過檢查才能繼續
# 如果不被允許，這行會拋出異常，後續代碼不會執行
must_allow(intent)

# 到這裡，執行已被授權
result = read_and_summarize_report()
```

**重要提醒**：這是一個執行守門員。如果你拿掉它，你的 agent 就是不安全的。
