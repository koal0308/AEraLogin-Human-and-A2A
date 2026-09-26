/**
 * AEra Chat Widget - Standalone JavaScript
 * Integriert in Landing Page - Kommuniziert mit VERA-KI über AEra Server
 * © 2025 VEra-Resonance Project
 */

// Configuration
const AERA_CHAT_CONFIG = {
    API_URL: '/api/vera-chat',  // Proxy endpoint on AEra Server (Port 8840)
    ENABLE_CONTEXT: true,
    DEBUG: true
};

// State
let aeraChatState = {
    isOpen: false,
    isProcessing: false,
    initialized: false
};

// Initialize Chat Widget
function initAeraChat() {
    // Prevent multiple initializations
    if (aeraChatState.initialized) {
        if (AERA_CHAT_CONFIG.DEBUG) {
            console.log('⚠️ AEra Chat already initialized, skipping');
        }
        return;
    }
    
    if (AERA_CHAT_CONFIG.DEBUG) {
        console.log('🌀 Initializing AEra Chat Widget');
    }
    
    // Create chat elements
    createChatButton();
    createChatPopup();
    attachEventListeners();
    
    aeraChatState.initialized = true;
    if (AERA_CHAT_CONFIG.DEBUG) {
        console.log('✅ AEra Chat initialization complete');
    }
}

// Create floating chat button
function createChatButton() {
    // Check if button already exists
    if (document.getElementById('aera-chat-button')) {
        if (AERA_CHAT_CONFIG.DEBUG) {
            console.log('⚠️ Chat button already exists, skipping creation');
        }
        return;
    }
    
    if (AERA_CHAT_CONFIG.DEBUG) {
        console.log('📍 Creating chat button...');
    }
    const button = document.createElement('button');
    button.id = 'aera-chat-button';
    button.className = 'aera-chat-button';
    button.innerHTML = '<span>🌀</span>';
    button.setAttribute('aria-label', 'Open AEra Chat');
    document.body.appendChild(button);
    if (AERA_CHAT_CONFIG.DEBUG) {
        console.log('✅ Chat button created and appended to body');
    }
}

// Create chat popup window
function createChatPopup() {
    // Check if popup already exists
    if (document.getElementById('aera-chat-popup')) {
        if (AERA_CHAT_CONFIG.DEBUG) {
            console.log('⚠️ Chat popup already exists, skipping creation');
        }
        return;
    }
    
    if (AERA_CHAT_CONFIG.DEBUG) {
        console.log('📍 Creating chat popup...');
    }
    
    const popup = document.createElement('div');
    popup.id = 'aera-chat-popup';
    popup.className = 'aera-chat-popup';
    
    popup.innerHTML = `
        <div class="aera-chat-header">
            <h3><span>🌀</span> VEra</h3>
            <button class="aera-chat-close" id="aera-chat-close" aria-label="Close chat">×</button>
        </div>
        
        <div class="aera-chat-messages" id="aera-chat-messages">
            <div class="aera-chat-message bot">
                Hello, I'm <span class="aera-highlight">VEra</span> 🌀<br><br>
                I help you understand the <strong>AEraLogIn-System</strong> – a decentralized identity system that maps <strong>social resonance on the blockchain</strong>.<br><br>
                What would you like to know?
            </div>
        </div>
        
        <div class="aera-typing" id="aera-typing">
            <span></span><span></span><span></span>
        </div>
        
        <div class="aera-chat-input-area">
            <input 
                type="text" 
                class="aera-chat-input" 
                id="aera-chat-input" 
                placeholder="Stelle deine Frage..."
                autocomplete="off"
            >
            <button class="aera-chat-send" id="aera-chat-send" aria-label="Send message">▶</button>
        </div>
    `;
    
    document.body.appendChild(popup);
}

// Attach event listeners
function attachEventListeners() {
    const button = document.getElementById('aera-chat-button');
    const closeBtn = document.getElementById('aera-chat-close');
    const sendBtn = document.getElementById('aera-chat-send');
    const input = document.getElementById('aera-chat-input');
    
    if (AERA_CHAT_CONFIG.DEBUG) {
        console.log('📎 Attaching event listeners...');
        console.log('Button:', button ? '✅' : '❌');
        console.log('Close:', closeBtn ? '✅' : '❌');
        console.log('Send:', sendBtn ? '✅' : '❌');
        console.log('Input:', input ? '✅' : '❌');
    }
    
    if (button) button.addEventListener('click', toggleChat);
    if (closeBtn) closeBtn.addEventListener('click', toggleChat);
    if (sendBtn) sendBtn.addEventListener('click', sendMessage);
    
    if (input) {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !aeraChatState.isProcessing) {
                sendMessage();
            }
        });
    }
    
    // Close on outside click
    document.addEventListener('click', (e) => {
        const popup = document.getElementById('aera-chat-popup');
        if (aeraChatState.isOpen && 
            popup && 
            !popup.contains(e.target) && 
            !button.contains(e.target)) {
            toggleChat();
        }
    });
}

// Toggle chat window
function toggleChat() {
    aeraChatState.isOpen = !aeraChatState.isOpen;
    const popup = document.getElementById('aera-chat-popup');
    const input = document.getElementById('aera-chat-input');
    
    if (AERA_CHAT_CONFIG.DEBUG) {
        console.log('🔄 Toggle chat - isOpen:', aeraChatState.isOpen);
        console.log('Popup found:', popup ? '✅' : '❌');
    }
    
    if (popup) {
        popup.classList.toggle('open', aeraChatState.isOpen);
        if (AERA_CHAT_CONFIG.DEBUG) {
            console.log('Popup classes:', popup.className);
        }
        if (aeraChatState.isOpen && input) {
            setTimeout(() => input.focus(), 300);
        }
    } else if (AERA_CHAT_CONFIG.DEBUG) {
        console.error('❌ Popup element not found!');
    }
}

// Convert Markdown to HTML
function markdownToHtml(markdown) {
    let html = markdown;
    
    // Headers (## Header -> <h3>)
    html = html.replace(/^### (.+)$/gm, '<h4>$1</h4>');
    html = html.replace(/^## (.+)$/gm, '<h3>$1</h3>');
    html = html.replace(/^# (.+)$/gm, '<h2>$1</h2>');
    
    // Bullet points FIRST (before italic conversion)
    // Match: * item or - item at start of line
    html = html.replace(/^[\*\-]\s+(.+)$/gm, '___LISTITEM___$1___ENDITEM___');
    
    // Bold (**text** -> <strong>)
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    
    // Italic (*text* -> <em>) - only if not part of list
    html = html.replace(/(?<!_)\*([^\*\n]+?)\*(?!_)/g, '<em>$1</em>');
    
    // Code (`code` -> <code>)
    html = html.replace(/`(.+?)`/g, '<code>$1</code>');
    
    // Links ([text](url) -> <a>)
    html = html.replace(/\[(.+?)\]\((.+?)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    
    // Convert list markers to <li>
    html = html.replace(/___LISTITEM___(.+?)___ENDITEM___/g, '<li>$1</li>');
    
    // Wrap consecutive <li> in <ul>
    html = html.replace(/(<li>[\s\S]+?<\/li>)(?![\s]*<li>)/g, '<ul>$1</ul>');
    
    // Line breaks (double newline -> <br><br>)
    html = html.replace(/\n\n/g, '<br><br>');
    
    // Single line breaks (but not inside lists)
    html = html.replace(/\n(?![<])/g, '<br>');
    
    return html;
}

// Add message to chat
function addMessage(text, isUser = false) {
    const messagesContainer = document.getElementById('aera-chat-messages');
    if (!messagesContainer) return;
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `aera-chat-message ${isUser ? 'user' : 'bot'}`;
    
    // Support HTML in bot messages (for bold, links, etc.)
    if (isUser) {
        messageDiv.textContent = text;
    } else {
        // Convert Markdown to HTML for bot messages
        messageDiv.innerHTML = markdownToHtml(text);
    }
    
    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// Show/hide typing indicator
function setTyping(isTyping) {
    const typingIndicator = document.getElementById('aera-typing');
    if (typingIndicator) {
        typingIndicator.classList.toggle('active', isTyping);
        
        // Scroll to show typing indicator
        const messagesContainer = document.getElementById('aera-chat-messages');
        if (messagesContainer && isTyping) {
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
    }
}

// Detect current page context (optional)
function detectPageContext() {
    if (!AERA_CHAT_CONFIG.ENABLE_CONTEXT) return null;
    
    // Check which section is visible
    const sections = ['hero', 'features', 'resonance', 'nft', 'blockchain', 'dashboard'];
    
    for (const sectionId of sections) {
        const element = document.getElementById(sectionId);
        if (element) {
            const rect = element.getBoundingClientRect();
            const isVisible = rect.top < window.innerHeight / 2 && rect.bottom > 0;
            if (isVisible) {
                return sectionId;
            }
        }
    }
    
    return null;
}

// Send message to API
async function sendMessage() {
    const input = document.getElementById('aera-chat-input');
    const sendBtn = document.getElementById('aera-chat-send');
    
    if (!input || aeraChatState.isProcessing) return;
    
    const message = input.value.trim();
    if (!message) return;
    
    // Update state
    aeraChatState.isProcessing = true;
    input.disabled = true;
    if (sendBtn) sendBtn.disabled = true;
    
    // Add user message
    addMessage(message, true);
    input.value = '';
    
    // Show typing
    setTyping(true);
    
    try {
        // Detect context
        const context = detectPageContext();
        
        // API Call to AEra Server (Proxy to VERA-KI)
        const response = await fetch(AERA_CHAT_CONFIG.API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: message,
                context: context
            })
        });
        
        if (!response.ok) {
            throw new Error(`API Error: ${response.status}`);
        }
        
        const data = await response.json();
        
        // Hide typing
        setTyping(false);
        
        // Check for error response
        if (data.error) {
            addMessage(`⚠️ ${data.error}`, false);
        } else if (data.response) {
            addMessage(data.response, false);
        } else {
            throw new Error('Invalid response format');
        }
        
        if (AERA_CHAT_CONFIG.DEBUG) {
            console.log('✅ Chat response received:', data);
        }
        
    } catch (error) {
        console.error('❌ AEra Chat Error:', error);
        setTyping(false);
        addMessage(
            'Entschuldigung, ich konnte deine Anfrage nicht verarbeiten. Der Chat-Service könnte offline sein. Bitte versuche es später erneut.',
            false
        );
    } finally {
        // Reset state
        aeraChatState.isProcessing = false;
        input.disabled = false;
        if (sendBtn) sendBtn.disabled = false;
        input.focus();
    }
}

// Initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAeraChat);
} else {
    initAeraChat();
}

if (AERA_CHAT_CONFIG.DEBUG) {
    console.log('🌀 AEra Chat Widget loaded');
}
