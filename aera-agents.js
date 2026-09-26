/*
 * AEra Agents — dashboard management module.
 *
 * SECURITY MODEL
 * --------------
 * This file is the OWNER'S MANAGEMENT INTERFACE. It is NOT an Agent Runtime.
 *
 *   Agent Runtime                      Dashboard (this file)
 *   -------------                      ---------------------
 *   generates the Ed25519 keypair      never generates a keypair
 *   keeps the PRIVATE key locally      never sees the private key
 *   sends the PUBLIC key to AEra       pastes the PUBLIC key the user provides
 *
 * Therefore:
 *   - No private key is ever generated, requested, displayed, stored or sent.
 *   - No Agent JWT is ever requested, stored or displayed. Agent authentication
 *     is the Runtime's job, not the dashboard's.
 *   - No LLM provider API key is ever handled. The provider is not part of the
 *     cryptographic identity and AEra does not store it.
 *   - Every mutating call goes to the EXISTING /api/agents/* endpoints and is
 *     authorised by the EXISTING owner challenge + EIP-191 signature flow.
 *     No new authentication mechanism, no bypass.
 *   - Ownership shown in the UI is advisory only; the backend is authoritative.
 */
(function () {
    'use strict';

    const AGENTS_API = '/api/agents';
    const DASHBOARD_API = '/api/dashboard/agents';

    // Populated from the backend so the UI can never offer a capability the
    // Agent Identity Layer would reject.
    let capabilityAllowlist = [];
    let agentsCache = [];

    // ---------------------------------------------------------------- utils

    function escapeHtml(value) {
        return String(value === null || value === undefined ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function truncateId(value, head, tail) {
        const s = String(value || '');
        const h = head || 22;
        const t = tail || 6;
        return s.length <= h + t + 1 ? s : s.slice(0, h) + '…' + s.slice(-t);
    }

    function formatDate(iso) {
        if (!iso) return '—';
        const d = new Date(iso);
        return isNaN(d.getTime()) ? escapeHtml(iso) : d.toLocaleDateString();
    }

    function copyText(text, label) {
        navigator.clipboard.writeText(text).then(
            () => showAgentToast('📋 ' + (label || 'Copied') + ' copied'),
            () => showAgentToast('❌ Could not copy', true)
        );
    }

    function showAgentToast(message, isError) {
        let el = document.getElementById('agentToast');
        if (!el) {
            el = document.createElement('div');
            el.id = 'agentToast';
            el.style.cssText =
                'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);' +
                'padding:12px 20px;border-radius:8px;font-size:13px;z-index:9999;' +
                'transition:opacity .3s;pointer-events:none;max-width:90vw;';
            document.body.appendChild(el);
        }
        el.style.background = isError ? 'rgba(239,68,68,.95)' : 'rgba(16,185,129,.95)';
        el.style.color = '#fff';
        el.textContent = message;
        el.style.opacity = '1';
        clearTimeout(el._t);
        el._t = setTimeout(() => { el.style.opacity = '0'; }, 2600);
    }

    // -------------------------------------------------- canonical JSON (RFC-ish)
    //
    // MUST be byte-identical to agent/crypto.py::canonical_json, because the
    // owner signature is verified against the bytes the backend rebuilds.
    // Parity with Python is asserted by
    // tests/agent/test_dashboard_agents.py::test_canonical_json_js_python_parity.

    function canonEscape(str) {
        let out = '"';
        for (const ch of str) {
            const cp = ch.codePointAt(0);
            if (cp >= 0xD800 && cp <= 0xDFFF) throw new Error('surrogate');
            if (cp === 0x22) out += '\\"';
            else if (cp === 0x5C) out += '\\\\';
            else if (cp === 0x08) out += '\\b';
            else if (cp === 0x09) out += '\\t';
            else if (cp === 0x0A) out += '\\n';
            else if (cp === 0x0C) out += '\\f';
            else if (cp === 0x0D) out += '\\r';
            else if (cp < 0x20) out += '\\u' + cp.toString(16).padStart(4, '0');
            else out += ch;
        }
        return out + '"';
    }

    function canonEncode(v) {
        if (v === true) return 'true';
        if (v === false) return 'false';
        if (typeof v === 'number') {
            if (!Number.isInteger(v)) throw new Error('float not allowed');
            return v.toString();
        }
        if (typeof v === 'string') return canonEscape(v.normalize('NFC'));
        if (Array.isArray(v)) return '[' + v.map(canonEncode).join(',') + ']';
        throw new Error('unsupported type in canonical payload');
    }

    function canonicalJson(obj) {
        const keys = Object.keys(obj).sort();
        return '{' + keys.map(k => canonEscape(k) + ':' + canonEncode(obj[k])).join(',') + '}';
    }

    // The owner challenge payload, exactly as agent/owner_challenges.py rebuilds it.
    function buildOwnerSignedPayload(challenge) {
        return canonicalJson({
            protocol: challenge.protocol,
            version: challenge.version,
            owner_wallet: challenge.owner_wallet,
            agent_id: challenge.agent_id || '',
            operation: challenge.operation,
            challenge_id: challenge.challenge_id,
            challenge: challenge.challenge,
            expires_at: challenge.expires_at,
            domain: challenge.domain
        });
    }

    // ------------------------------------------------------------ owner flow

    function currentWallet() {
        return (typeof connectedWallet !== 'undefined' && connectedWallet) || null;
    }

    async function apiJson(url, options) {
        const res = await fetch(url, options);
        let body = null;
        try { body = await res.json(); } catch (e) { /* non-JSON error page */ }
        return { ok: res.ok, status: res.status, body: body };
    }

    function agentErrorOf(result) {
        const b = result.body || {};
        const detail = b.detail;
        if (detail && typeof detail === 'object' && detail.agent_error) return detail.agent_error;
        if (typeof detail === 'string') return detail;
        if (b.error) return b.error;
        return 'http_' + result.status;
    }

    /**
     * Run the EXISTING owner challenge + signature flow for one operation.
     * Returns { owner_wallet, owner_challenge_id, owner_signature }.
     * Throws Error(code) on failure.
     */
    async function authorizeOwnerOperation(operation, agentId) {
        const wallet = currentWallet();
        if (!wallet) throw new Error('wallet_not_connected');

        const challengeRes = await apiJson(AGENTS_API + '/owner-challenge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                owner_wallet: wallet,
                operation: operation,
                agent_id: agentId || null
            })
        });
        if (!challengeRes.ok) throw new Error(agentErrorOf(challengeRes));

        const challenge = challengeRes.body;
        const message = buildOwnerSignedPayload(challenge);

        // personal_sign encodes a plain string as UTF-8. The canonical payload
        // is ASCII by construction here, so UTF-8 == the bytes the backend
        // verifies. Fail loudly rather than produce a signature over different
        // bytes than the server will check.
        if (/[^\x20-\x7E]/.test(message)) throw new Error('non_ascii_challenge_payload');

        const signature = await robustWalletSign(message, wallet);
        if (!signature) throw new Error('signature_rejected');

        return {
            owner_wallet: wallet,
            owner_challenge_id: challenge.challenge_id,
            owner_signature: signature
        };
    }

    // --------------------------------------------------------------- loading

    async function loadMyAgents() {
        const container = document.getElementById('myAgentsList');
        if (!container) return;

        const token = (typeof getAuthToken === 'function') ? getAuthToken() : null;
        if (!token) {
            container.innerHTML = emptyState('Connect your wallet to view your Agents.');
            return;
        }

        container.innerHTML = loadingState('Loading your Agents…');

        try {
            const res = await apiJson(DASHBOARD_API, {
                headers: { 'Authorization': 'Bearer ' + token }
            });
            if (res.status === 401) {
                container.innerHTML = emptyState('Session expired. Please reconnect your wallet.');
                return;
            }
            if (!res.ok || !res.body || !res.body.success) {
                container.innerHTML = errorState('Could not load Agents (' + agentErrorOf(res) + ').');
                return;
            }

            capabilityAllowlist = res.body.capability_allowlist || [];
            agentsCache = res.body.agents || [];
            renderCapabilityCheckboxes();

            if (agentsCache.length === 0) {
                container.innerHTML = emptyState(
                    'No Agents yet. Create your first Agent above.<br>' +
                    '<span style="font-size:11px;opacity:.7;">Your Agent Runtime generates the keypair — ' +
                    'AEra only ever receives the public key.</span>');
                return;
            }
            container.innerHTML = agentsCache.map(renderAgentCard).join('');
        } catch (e) {
            container.innerHTML = errorState('Network error while loading Agents.');
        }
    }

    function loadingState(msg) {
        return '<div style="text-align:center;padding:24px;color:rgba(240,244,255,.5);">⏳ ' +
            escapeHtml(msg) + '</div>';
    }
    function emptyState(html) {
        return '<div style="text-align:center;padding:30px;color:rgba(240,244,255,.5);"><p>' +
            html + '</p></div>';
    }
    function errorState(msg) {
        return '<div style="text-align:center;padding:24px;color:#ef4444;">❌ ' +
            escapeHtml(msg) + '</div>';
    }

    // ------------------------------------------------------------- rendering

    function statusBadge(status) {
        const active = status === 'active';
        const bg = active ? 'rgba(16,185,129,.2)' : 'rgba(239,68,68,.2)';
        const fg = active ? 'var(--success)' : '#ef4444';
        const label = active ? '● Active' : '● ' + escapeHtml(status || 'unknown');
        return '<span style="font-size:10px;padding:3px 8px;background:' + bg +
            ';color:' + fg + ';border-radius:4px;white-space:nowrap;">' + label + '</span>';
    }

    function copyRow(label, value) {
        if (!value) {
            return '<div style="margin-bottom:8px;"><label style="font-size:10px;' +
                'color:rgba(240,244,255,.5);display:block;">' + escapeHtml(label) +
                ':</label><span style="font-size:11px;opacity:.5;">—</span></div>';
        }
        const safe = escapeHtml(value).replace(/'/g, '&#39;');
        return '<div style="margin-bottom:8px;">' +
            '<label style="font-size:10px;color:rgba(240,244,255,.5);display:block;">' +
            escapeHtml(label) + ':</label>' +
            '<code style="font-size:11px;color:var(--secondary);word-break:break-all;">' +
            escapeHtml(truncateId(value)) + '</code> ' +
            '<button onclick="AEraAgents.copy(\'' + safe + '\',\'' + escapeHtml(label) + '\')" ' +
            'style="background:none;border:none;cursor:pointer;font-size:11px;opacity:.6;" ' +
            'title="Copy full value">📋</button></div>';
    }

    function renderAgentCard(agent) {
        const isActive = agent.status === 'active';
        const caps = (agent.capabilities || []).map(c =>
            '<span style="font-size:10px;padding:2px 6px;background:rgba(99,102,241,.15);' +
            'border:1px solid rgba(99,102,241,.35);border-radius:4px;margin-right:4px;' +
            'display:inline-block;margin-bottom:4px;">✓ ' + escapeHtml(c) + '</span>').join('');
        const aid = escapeHtml(agent.agent_id);

        const manageBtn = isActive
            ? '<button onclick="AEraAgents.toggleManage(\'' + aid + '\')" class="cta-button" ' +
              'style="flex:1;padding:6px;font-size:11px;">⚙️ Manage</button>'
            : '<button disabled class="cta-button" style="flex:1;padding:6px;font-size:11px;' +
              'opacity:.4;cursor:not-allowed;" title="Agent is revoked">⚙️ Manage</button>';

        return '' +
        '<div style="padding:16px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.1);' +
        'border-radius:8px;" id="agentCard-' + aid + '">' +
            '<div style="display:flex;justify-content:space-between;align-items:flex-start;' +
            'gap:8px;margin-bottom:10px;flex-wrap:wrap;">' +
                '<h4 style="margin:0;color:var(--light);font-size:14px;">🤖 ' +
                    escapeHtml(agent.label || 'Unnamed Agent') + '</h4>' +
                statusBadge(agent.status) +
            '</div>' +
            copyRow('AGENT ID', agent.agent_id) +
            copyRow('ACTIVE KEY', agent.active_key_id) +
            '<div style="margin-bottom:8px;">' +
                '<label style="font-size:10px;color:rgba(240,244,255,.5);display:block;margin-bottom:4px;">' +
                'CAPABILITIES:</label>' + (caps || '<span style="font-size:11px;opacity:.5;">—</span>') +
            '</div>' +
            '<div style="font-size:10px;color:rgba(240,244,255,.45);margin-bottom:10px;">' +
                'Created ' + formatDate(agent.created_at) +
                ' · ' + agent.active_key_count + ' active key' +
                (agent.active_key_count === 1 ? '' : 's') +
            '</div>' +
            '<div style="display:flex;gap:8px;flex-wrap:wrap;">' + manageBtn + '</div>' +
            '<div id="agentManage-' + aid + '" style="display:none;margin-top:12px;' +
            'padding-top:12px;border-top:1px solid rgba(255,255,255,.1);"></div>' +
        '</div>';
    }

    function renderManagePanel(agent) {
        const aid = escapeHtml(agent.agent_id);
        const keyRows = (agent.keys || []).map(k => {
            const isActive = k.status === 'active';
            const revokeBtn = isActive && agent.active_key_count > 1
                ? '<button onclick="AEraAgents.revokeKey(\'' + aid + '\',\'' +
                  escapeHtml(k.key_id) + '\')" style="background:rgba(239,68,68,.15);' +
                  'border:1px solid #ef4444;color:#ef4444;border-radius:4px;font-size:10px;' +
                  'padding:3px 8px;cursor:pointer;">Revoke</button>'
                : (isActive
                    ? '<span style="font-size:10px;opacity:.45;" title="An active Agent must keep at least one active key">last active key</span>'
                    : '<span style="font-size:10px;opacity:.45;">revoked</span>');
            return '<div style="display:flex;justify-content:space-between;align-items:center;' +
                'gap:8px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.06);flex-wrap:wrap;">' +
                '<code style="font-size:10px;color:' + (isActive ? 'var(--secondary)' : 'rgba(240,244,255,.4)') +
                ';word-break:break-all;">' + escapeHtml(truncateId(k.key_id, 18, 6)) + '</code>' +
                revokeBtn + '</div>';
        }).join('');

        const capBoxes = capabilityAllowlist.map(c => {
            const checked = (agent.capabilities || []).indexOf(c) !== -1 ? ' checked' : '';
            return '<label style="display:block;font-size:11px;margin-bottom:4px;cursor:pointer;">' +
                '<input type="checkbox" data-agent-cap="' + aid + '" value="' + escapeHtml(c) + '"' +
                checked + ' style="margin-right:6px;">' + escapeHtml(c) + '</label>';
        }).join('');

        return '' +
        '<div style="display:grid;gap:14px;">' +
            '<div>' +
                '<h5 style="margin:0 0 6px;font-size:12px;color:var(--secondary);">🔑 Keys</h5>' +
                '<p style="font-size:10px;opacity:.6;margin:0 0 8px;">' +
                    'Rotating a key changes <code>key_id</code> only — <code>agent_id</code> ' +
                    'and the Agent\'s identity stay the same.' +
                '</p>' +
                keyRows +
                '<div style="margin-top:10px;">' +
                    '<label style="display:block;font-size:11px;margin-bottom:4px;' +
                    'color:rgba(240,244,255,.7);">New Ed25519 public key ' +
                    '(<code>ed25519:&lt;base64url&gt;</code>)</label>' +
                    '<input type="text" id="rotateKeyInput-' + aid + '" ' +
                    'placeholder="ed25519:..." autocomplete="off" ' +
                    'style="width:100%;padding:8px;border:1px solid rgba(255,255,255,.1);' +
                    'border-radius:6px;font-size:12px;background:rgba(255,255,255,.05);' +
                    'color:var(--light);margin-bottom:6px;">' +
                    '<p style="font-size:10px;color:#f59e0b;margin:0 0 8px;">' +
                        '🔒 Paste the <strong>public</strong> key from your Agent Runtime. ' +
                        'Never paste a private key here — AEra never needs it.' +
                    '</p>' +
                    '<div style="display:flex;gap:8px;flex-wrap:wrap;">' +
                        '<button onclick="AEraAgents.addKey(\'' + aid + '\')" class="cta-button" ' +
                        'style="flex:1;padding:6px;font-size:11px;">➕ Add Key</button>' +
                        '<button onclick="AEraAgents.rotateKey(\'' + aid + '\')" class="cta-button" ' +
                        'style="flex:1;padding:6px;font-size:11px;background:rgba(245,158,11,.2);' +
                        'border:1px solid #f59e0b;color:#f59e0b;">🔄 Rotate Active Key</button>' +
                    '</div>' +
                '</div>' +
            '</div>' +
            '<div>' +
                '<h5 style="margin:0 0 6px;font-size:12px;color:var(--secondary);">🎛️ Capabilities</h5>' +
                capBoxes +
                '<button onclick="AEraAgents.saveCapabilities(\'' + aid + '\')" class="cta-button" ' +
                'style="width:100%;padding:6px;font-size:11px;margin-top:6px;">💾 Save Capabilities</button>' +
            '</div>' +
            '<div>' +
                '<h5 style="margin:0 0 6px;font-size:12px;color:#ef4444;">⚠️ Danger zone</h5>' +
                '<button onclick="AEraAgents.revokeAgent(\'' + aid + '\')" class="cta-button" ' +
                'style="width:100%;padding:6px;font-size:11px;background:rgba(239,68,68,.15);' +
                'border:1px solid #ef4444;color:#ef4444;">🗑️ Revoke Agent</button>' +
            '</div>' +
            '<div id="agentOpStatus-' + aid + '" style="font-size:11px;"></div>' +
        '</div>';
    }

    function renderCapabilityCheckboxes() {
        const box = document.getElementById('registerAgentCapabilities');
        if (!box) return;
        if (!capabilityAllowlist.length) {
            box.innerHTML = '<span style="font-size:11px;opacity:.5;">—</span>';
            return;
        }
        box.innerHTML = capabilityAllowlist.map(c =>
            '<label style="display:inline-block;font-size:11px;margin:0 12px 6px 0;cursor:pointer;">' +
            '<input type="checkbox" class="agent-register-cap" value="' + escapeHtml(c) + '" ' +
            'checked style="margin-right:6px;">' + escapeHtml(c) + '</label>').join('');
    }

    // ------------------------------------------------------------ operations

    function opStatus(agentId, message, kind) {
        const el = document.getElementById('agentOpStatus-' + agentId);
        if (!el) return;
        const colour = kind === 'error' ? '#ef4444'
            : kind === 'ok' ? 'var(--success)' : 'rgba(240,244,255,.7)';
        el.innerHTML = '<span style="color:' + colour + ';">' + escapeHtml(message) + '</span>';
    }

    function findAgent(agentId) {
        return agentsCache.filter(a => a.agent_id === agentId)[0] || null;
    }

    function toggleManage(agentId) {
        const panel = document.getElementById('agentManage-' + agentId);
        if (!panel) return;
        if (panel.style.display === 'block') { panel.style.display = 'none'; return; }
        const agent = findAgent(agentId);
        if (!agent) return;
        panel.innerHTML = renderManagePanel(agent);
        panel.style.display = 'block';
    }

    function looksLikePublicKey(value) {
        return /^ed25519:[A-Za-z0-9_-]{20,}$/.test(value);
    }

    /** Refuse anything that looks like private key material. */
    function rejectPrivateKeyMaterial(value) {
        const v = String(value || '');
        if (/PRIVATE KEY|BEGIN [A-Z ]*KEY|ed25519-priv|privkey|private/i.test(v)) {
            return true;
        }
        return false;
    }

    async function registerAgent() {
        const statusEl = document.getElementById('registerAgentStatus');
        const nameEl = document.getElementById('registerAgentName');
        const keyEl = document.getElementById('registerAgentPublicKey');
        if (!statusEl || !nameEl || !keyEl) return;

        const setStatus = (msg, kind) => {
            statusEl.style.display = 'block';
            statusEl.innerHTML = '<span style="color:' +
                (kind === 'error' ? '#ef4444' : kind === 'ok' ? 'var(--success)' : 'rgba(240,244,255,.7)') +
                ';">' + escapeHtml(msg) + '</span>';
        };

        const label = nameEl.value.trim();
        const publicKey = keyEl.value.trim();
        const capabilities = Array.prototype.slice
            .call(document.querySelectorAll('.agent-register-cap:checked'))
            .map(cb => cb.value);

        if (!currentWallet()) { setStatus('❌ Connect your wallet first.', 'error'); return; }
        if (label.length < 3) { setStatus('❌ Agent name must be at least 3 characters.', 'error'); return; }
        if (rejectPrivateKeyMaterial(publicKey)) {
            setStatus('🛑 That looks like a PRIVATE key. Never share it — AEra only needs the public key.', 'error');
            keyEl.value = '';
            return;
        }
        if (!looksLikePublicKey(publicKey)) {
            setStatus('❌ Public key must look like ed25519:<base64url>.', 'error');
            return;
        }

        try {
            setStatus('⏳ Waiting for your wallet signature…');
            const auth = await authorizeOwnerOperation('register', null);

            setStatus('⏳ Registering Agent…');
            const res = await apiJson(AGENTS_API + '/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({}, auth, {
                    public_key: publicKey,
                    label: label,
                    capabilities: capabilities.length ? capabilities : null
                }))
            });
            if (!res.ok) { setStatus('❌ Registration failed: ' + agentErrorOf(res), 'error'); return; }

            setStatus('✅ Agent registered: ' + truncateId(res.body.agent_id), 'ok');
            nameEl.value = '';
            keyEl.value = '';
            await loadMyAgents();
        } catch (e) {
            setStatus('❌ ' + (e && e.message ? e.message : 'registration_failed'), 'error');
        }
    }

    async function addKey(agentId) {
        const input = document.getElementById('rotateKeyInput-' + agentId);
        if (!input) return;
        const publicKey = input.value.trim();
        if (rejectPrivateKeyMaterial(publicKey)) {
            opStatus(agentId, '🛑 That looks like a PRIVATE key. Never paste it here.', 'error');
            input.value = '';
            return;
        }
        if (!looksLikePublicKey(publicKey)) {
            opStatus(agentId, '❌ Public key must look like ed25519:<base64url>.', 'error');
            return;
        }
        try {
            opStatus(agentId, '⏳ Waiting for your wallet signature…');
            const auth = await authorizeOwnerOperation('key_add', agentId);
            const res = await apiJson(AGENTS_API + '/' + encodeURIComponent(agentId) + '/keys', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({}, auth, { public_key: publicKey }))
            });
            if (!res.ok) { opStatus(agentId, '❌ Add key failed: ' + agentErrorOf(res), 'error'); return; }
            opStatus(agentId, '✅ Key added. agent_id unchanged.', 'ok');
            input.value = '';
            await refreshAndReopen(agentId);
        } catch (e) {
            opStatus(agentId, '❌ ' + (e && e.message ? e.message : 'key_add_failed'), 'error');
        }
    }

    async function rotateKey(agentId) {
        const agent = findAgent(agentId);
        const input = document.getElementById('rotateKeyInput-' + agentId);
        if (!agent || !input) return;
        if (!agent.active_key_id) { opStatus(agentId, '❌ No active key to rotate.', 'error'); return; }

        const publicKey = input.value.trim();
        if (rejectPrivateKeyMaterial(publicKey)) {
            opStatus(agentId, '🛑 That looks like a PRIVATE key. Never paste it here.', 'error');
            input.value = '';
            return;
        }
        if (!looksLikePublicKey(publicKey)) {
            opStatus(agentId, '❌ Public key must look like ed25519:<base64url>.', 'error');
            return;
        }
        if (!window.confirm(
            'Rotate the active signing key of "' + (agent.label || agentId) + '"?\n\n' +
            'The current key (' + truncateId(agent.active_key_id, 18, 6) + ') will be revoked ' +
            'and replaced by the key you pasted.\n\n' +
            'agent_id stays the same — only key_id changes.')) return;

        try {
            opStatus(agentId, '⏳ Waiting for your wallet signature…');
            const auth = await authorizeOwnerOperation('key_rotate', agentId);
            const res = await apiJson(AGENTS_API + '/' + encodeURIComponent(agentId) + '/keys/rotate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({}, auth, {
                    new_public_key: publicKey,
                    revoke_key_id: agent.active_key_id
                }))
            });
            if (!res.ok) { opStatus(agentId, '❌ Rotation failed: ' + agentErrorOf(res), 'error'); return; }
            opStatus(agentId, '✅ Key rotated. agent_id unchanged, key_id changed.', 'ok');
            input.value = '';
            await refreshAndReopen(agentId);
        } catch (e) {
            opStatus(agentId, '❌ ' + (e && e.message ? e.message : 'rotate_failed'), 'error');
        }
    }

    async function revokeKey(agentId, keyId) {
        const agent = findAgent(agentId);
        if (!agent) return;
        if (!window.confirm(
            'Revoke key ' + truncateId(keyId, 18, 6) + '?\n\n' +
            'Any Agent JWT issued for this key is revoked immediately.\n' +
            'The Agent itself and its agent_id are not affected.')) return;
        try {
            opStatus(agentId, '⏳ Waiting for your wallet signature…');
            const auth = await authorizeOwnerOperation('key_revoke', agentId);
            const res = await apiJson(
                AGENTS_API + '/' + encodeURIComponent(agentId) + '/keys/' + encodeURIComponent(keyId), {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    // public_key is required by the shared request model but is
                    // not used for key revocation by the backend.
                    body: JSON.stringify(Object.assign({}, auth, { public_key: 'ed25519:unused' }))
                });
            if (!res.ok) { opStatus(agentId, '❌ Key revoke failed: ' + agentErrorOf(res), 'error'); return; }
            opStatus(agentId, '✅ Key revoked.', 'ok');
            await refreshAndReopen(agentId);
        } catch (e) {
            opStatus(agentId, '❌ ' + (e && e.message ? e.message : 'key_revoke_failed'), 'error');
        }
    }

    async function saveCapabilities(agentId) {
        const boxes = document.querySelectorAll('[data-agent-cap="' + agentId + '"]:checked');
        const capabilities = Array.prototype.slice.call(boxes).map(cb => cb.value);
        if (!capabilities.length) {
            opStatus(agentId, '❌ Select at least one capability.', 'error');
            return;
        }
        try {
            opStatus(agentId, '⏳ Waiting for your wallet signature…');
            const auth = await authorizeOwnerOperation('capabilities', agentId);
            const res = await apiJson(
                AGENTS_API + '/' + encodeURIComponent(agentId) + '/capabilities', {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(Object.assign({}, auth, { capabilities: capabilities }))
                });
            if (!res.ok) { opStatus(agentId, '❌ Update failed: ' + agentErrorOf(res), 'error'); return; }
            opStatus(agentId, '✅ Capabilities updated.', 'ok');
            await refreshAndReopen(agentId);
        } catch (e) {
            opStatus(agentId, '❌ ' + (e && e.message ? e.message : 'capabilities_failed'), 'error');
        }
    }

    async function revokeAgent(agentId) {
        const agent = findAgent(agentId);
        if (!agent) return;
        if (!window.confirm(
            'Revoke "' + (agent.label || agentId) + '"?\n\n' +
            'This permanently disables the Agent\'s active identity and prevents it from ' +
            'authenticating or communicating through AEra.\n\n' +
            'All its keys and all issued Agent JWTs are revoked immediately.\n' +
            'Historical identity data is preserved; this cannot be undone.')) return;
        try {
            opStatus(agentId, '⏳ Waiting for your wallet signature…');
            const auth = await authorizeOwnerOperation('agent_revoke', agentId);
            const res = await apiJson(AGENTS_API + '/' + encodeURIComponent(agentId), {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({}, auth, { public_key: 'ed25519:unused' }))
            });
            if (!res.ok) { opStatus(agentId, '❌ Revoke failed: ' + agentErrorOf(res), 'error'); return; }
            showAgentToast('✅ Agent revoked');
            await loadMyAgents();
        } catch (e) {
            opStatus(agentId, '❌ ' + (e && e.message ? e.message : 'revoke_failed'), 'error');
        }
    }

    async function refreshAndReopen(agentId) {
        await loadMyAgents();
        const panel = document.getElementById('agentManage-' + agentId);
        const agent = findAgent(agentId);
        if (panel && agent && agent.status === 'active') {
            panel.innerHTML = renderManagePanel(agent);
            panel.style.display = 'block';
        }
    }

    // ------------------------------------------------------------ key help
    //
    // Purely presentational. The dashboard explains where a public key comes
    // from; it never generates, requests or handles one half of a keypair.

    function toggleKeyHelp() {
        const box = document.getElementById('agentKeyHelp');
        const toggle = document.getElementById('agentKeyHelpToggle');
        if (!box) return;
        const open = box.style.display === 'block';
        box.style.display = open ? 'none' : 'block';
        if (toggle) {
            toggle.textContent = open
                ? 'How do I get a public key?'
                : 'Hide help';
        }
    }

    function copyKeygenSnippet() {
        const pre = document.getElementById('agentKeygenSnippet');
        if (!pre) return;
        copyText(pre.textContent, 'Key generation command');
    }

    // ----------------------------------------------------------------- export

    window.AEraAgents = {
        load: loadMyAgents,
        register: registerAgent,
        toggleManage: toggleManage,
        addKey: addKey,
        rotateKey: rotateKey,
        revokeKey: revokeKey,
        saveCapabilities: saveCapabilities,
        revokeAgent: revokeAgent,
        copy: copyText,
        toggleKeyHelp: toggleKeyHelp,
        copyKeygenSnippet: copyKeygenSnippet,
        // exported for the Python↔JS canonical-JSON parity test
        _canonicalJson: canonicalJson,
        _buildOwnerSignedPayload: buildOwnerSignedPayload,
        // shared with aera-agent-enroll.js so pairing uses the SAME owner
        // challenge + wallet signature flow, not a second implementation
        _authorizeOwnerOperation: authorizeOwnerOperation,
        _agentErrorOf: agentErrorOf,
        _escapeHtml: escapeHtml,
        _toast: showAgentToast
    };

    // Keep the dashboard's existing global-function calling convention working.
    window.loadMyAgents = loadMyAgents;
    window.registerAgent = registerAgent;
})();
