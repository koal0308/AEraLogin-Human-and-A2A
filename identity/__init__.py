"""AEra Human Identity layer (Phase 0.1 foundation).

A Human Identity is the stable, provider-neutral identity of a human owner.
It is NOT a wallet address, an e-mail address, an external account, an agent
or a runtime. Authentication providers (today: wallet only) are *bound* to a
Human Identity; they never become agent or runtime credentials.

Layering (top to bottom):

    Human authentication (provider)  ->  Human Identity (human_id)
        ->  Owner authorization (existing wallet owner challenge)
        ->  Agent identity (agent/)  ->  Runtime identity (agent_runtime/)

Nothing in this package is consulted by the Agent JWT, the runtime or the A2A
gateway: those keep reasoning about agents, keys and peers only.
"""
