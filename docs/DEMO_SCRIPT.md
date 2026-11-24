# ProofPilot demo script (3–4 minutes)

## Before presenting

Install the dependencies and start the local app as described in [QUICKSTART.md](QUICKSTART.md). Open the URL printed by `scripts/run_local.py`. Keep the launcher terminal visible. The demo is local and uses fixed fixture data; do not select the AgentCore provider for this flow.

## 0:00–0:25 — Introduce ProofPilot

**Say:** “ProofPilot is a security and verification layer for AI browser agents. Webpages are untrusted: they can contain instructions that try to redirect an agent away from the user's task. ProofPilot makes the intended action reviewable, binds approval to that exact action, and checks the saved result afterward.”

**Show:** The ProofPilot workspace. Point out the task, evidence, Warrant review, and execution progress areas.

## 0:25–0:55 — Start and initialize the task

**Say:** “This is the local demonstration. The laptop facts are fixed simulated data, so we can focus on the authorization and verification flow without depending on external search or AWS.”

**Do:** If the app is not already running, open PowerShell at the project root and run `python scripts\run_local.py`; open the printed local URL. In the workspace click **Load simulated demo**.

**Show:** The task goal and candidate results. Briefly call out that the Dell fixture satisfies both constraints, the Lenovo fixture misses the RAM minimum, and the MSI current price exceeds budget while its older promotional price is excluded from current-price evaluation.

## 0:55–1:25 — Show the Proof Contract and prepare an action

**Say:** “The Proof Contract captures the task's hard requirements and permitted actions. A result alone cannot authorize a write; a separate action contract must fit the task and its evidence.”

**Do:** Scroll to **Proof Contract** and show the price and RAM requirements. In **Demo action contract**, choose a supported candidate such as Dell G16 and click **Prepare exact action**.

**Show:** The exact form payload, associated evidence, preconditions, expected postconditions, approval digest, and idempotency reference. Explain that preparation only creates a reviewable request; it does not submit the form.

## 1:25–1:55 — Review and approve the Warrant

**Say:** “The Warrant is a typed, deterministic plan for this one local form workflow. Its contract hash and HMAC signature bind it to the current task, Proof Contract, action, target, parameters, and expiry. My approval sends the exact Warrant hash shown here.”

**Do:** Show the Warrant plan and signature validation, then click **Approve Warrant**.

**Show:** The action changes to approved and the reviewed Warrant hash is recorded. Note that approval is specific to the reviewed contract; it is not a blanket permission for future tasks.

## 1:55–2:50 — Execute and show the adversarial denial

**Say:** “The simulated form includes a hidden instruction asking the agent to abandon the comparison and send dummy data to an attacker-controlled destination. In this demo, that attempt is sent directly into the policy evaluator. It is not a real navigation or network request.”

**Do:** Click **Execute approved action** and wait for the receipt and defense event to appear.

**Show:** The hidden instruction excerpt, the proposed `navigate` to `attacker.invalid`, and the recorded `DOMAIN_BOUNDARY` denial. Explain: “The signed plan allows only the exact local loopback steps. This target is outside that boundary, so the attempt is denied and persisted before dispatch. The planned action remains the original approved local submission.”

## 2:50–3:25 — Show verification and receipt

**Say:** “The approved action continues. After the local form accepts it, ProofPilot makes a separate HTTPX readback of the saved record and compares its fields with the approved payload. The receipt ties together the action, approved Warrant hash, execution, verification, and idempotency reference.”

**Do:** Point to **Independent verification** and **Persisted proof receipt**. Show the verified outcome, record ID, receipt ID, and persisted policy decision.

## 3:25–3:40 — Close

**Say:** “This is a focused local prototype, not a claim of complete real-world prompt-injection protection. It demonstrates a useful principle: an agent may encounter untrusted instructions, but only a reviewed action inside an explicit policy boundary should execute. AI that acts. Warrant that proves.”

**Show:** Leave the receipt and denial visible together.
