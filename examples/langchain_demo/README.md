# LangChain Demo

Demonstrates `KestralCallback` for automatic prompt injection scanning in LangChain chains.

## Setup

```bash
pip install -e ".[langchain]" langchain-openai   # from the repository root
```

## Run

```bash
python examples/langchain_demo/app.py
```

## How It Works

The callback hooks into three LangChain lifecycle events:

| Event | Gate | Action |
|---|---|---|
| `on_llm_start` | Input gate | Scans prompts before LLM call; raises `ValueError` on detection |
| `on_tool_end` | Data gate | Scans tool output for indirect injection |
| `on_llm_end` | Output gate | Checks LLM response for canary token leakage |

Pass `callbacks=[callback]` to any LangChain `LLM`, `ChatModel`, or `AgentExecutor`.
