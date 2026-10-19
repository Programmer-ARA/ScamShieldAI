"""Fetch.ai uAgent starter.

This is a transport-neutral starter while you confirm the exact chat/ACP setup
required by the current Fetch-A-Thon hackpack. The local engine works without it.

Install and follow the current official ASI:One-compatible example:
https://uagents.fetch.ai/docs/examples/asi-1
Do not assume a generic uAgent automatically satisfies the event's ACP requirement.
"""
from uagents import Agent, Context
from scam_engine import investigate
import json
import os
from dotenv import load_dotenv

load_dotenv()

AGENT_NAME = os.getenv("SCAMSHIELD_AGENT_NAME", "scamshield-investigator")
AGENT_SEED = os.getenv("SCAMSHIELD_AGENT_SEED")

if not AGENT_SEED:
    raise RuntimeError(
        "Set SCAMSHIELD_AGENT_SEED in .env before starting the agent. "
        "Use a private random seed and never publish it."
    )

agent = Agent(
    name=AGENT_NAME,
    seed=AGENT_SEED,
    port=int(os.getenv("SCAMSHIELD_PORT", "8000")),
    endpoint=os.getenv("SCAMSHIELD_ENDPOINT", "http://127.0.0.1:8000/submit"),
)

# Development message schema. Replace/bridge this with the official
# ASI:One-compatible chat protocol from the hackathon docs before submission.
from uagents import Model

class InvestigationRequest(Model):
    message: str

class InvestigationResponse(Model):
    report_json: str

@agent.on_message(model=InvestigationRequest, replies=InvestigationResponse)
async def handle_investigation(ctx: Context, sender: str, msg: InvestigationRequest):
    try:
        report = investigate(msg.message)
        await ctx.send(sender, InvestigationResponse(
            report_json=json.dumps(report, ensure_ascii=False)
        ))
    except ValueError as exc:
        await ctx.send(sender, InvestigationResponse(
            report_json=json.dumps({"error": str(exc)})
        ))

if __name__ == "__main__":
    agent.run()
