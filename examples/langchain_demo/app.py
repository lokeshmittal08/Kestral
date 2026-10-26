"""LangChain integration demo using KestralCallback.

This example shows how to attach kestral as a LangChain callback handler
so that prompts and tool results are automatically scanned for injection.
No LLM is called — the focus is on the setup pattern.
"""

from kestral import KestralEngine
from kestral.integrations.langchain_callback import KestralCallback

# Step 1: Create a kestral engine (uses default config).
engine = KestralEngine()

# Step 2: Create the LangChain callback handler.
# - mode="block" raises ValueError on detection, halting the chain.
# - scan_tool_results=True scans tool output for indirect injection.
# - enable_canary=True checks LLM output for canary token leakage.
callback = KestralCallback(
    engine=engine,
    mode="block",
    scan_tool_results=True,
    enable_canary=False,  # set True if you inject canary tokens into your system prompt
)

# Step 3: Attach the callback to any LangChain chain or LLM.
# With a ChatOpenAI model:
#
#   from langchain_openai import ChatOpenAI
#   llm = ChatOpenAI(model="gpt-4o", callbacks=[callback])
#
# With an agent:
#
#   from langchain.agents import AgentExecutor
#   agent_executor = AgentExecutor(agent=agent, tools=tools, callbacks=[callback])
#
# The callback fires automatically:
#   - on_llm_start  -> scans every prompt before it reaches the LLM (input gate)
#   - on_tool_end   -> scans tool output for hidden injection (data gate)
#   - on_llm_end    -> checks for canary leakage in LLM responses (output gate)
#   - on_chain_error -> logs when kestral blocks a chain

print("KestralCallback is ready to be attached to any LangChain chain.")
print(f"Engine has {len(engine.list_detectors())} detectors loaded.")
