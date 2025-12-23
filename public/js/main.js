const socket = io({ autoConnect: false });
const ratchet = new RatchetSession();
let myKeyPair;
let typingTimeout;

// DOM Elements
const uiStatus = document.getElementById('typing-indicator');
const uiConnStatusText = document.getElementById('conn-status-text');
const uiChat = document.getElementById('chat-box');
const uiInput = document.getElementById('msg-input');
const uiBtn = document.getElementById('send-btn');
const uiPublicKey = document.getElementById('ui-public-key');
const uiPrivateKey = document.getElementById('ui-private-key'); 
const uiSessionKey = document.getElementById('ui-session-key'); 
const uiNetwork = document.getElementById('network-log-content');

// 1. Initialization
async function init() {
    try {
        uiConnStatusText.innerText = "Generating Keys...";
        uiPublicKey.innerText = "Generating ECDH P-256...";
        
        myKeyPair = await generateIdentityKeyPair();
        
        // EXPORT PUBLIC KEY
        const pubKeyStr = await exportKey(myKeyPair.publicKey);
        uiPublicKey.innerText = pubKeyStr; // FULL KEY
        
        // EXPORT PRIVATE KEY 
        const privKeyStr = await exportPrivateKey(myKeyPair.privateKey);
        uiPrivateKey.innerText = privKeyStr; // FULL KEY

        socket.connect();
    } catch (err) {
        console.error("Init Error:", err);
    }
}

init();

// 2. Connection
socket.on('connect', async () => {
    uiConnStatusText.innerText = "Online. Broadcasting...";
    await broadcastHandshake();
});

socket.on('new-peer', async () => {
    await broadcastHandshake();
});

// 3. Handshake
socket.on('signal-handshake', async (data) => {
    if (data.sender === socket.id) return;
    try {
        const peerPublicKey = await importKey(data.publicKey);
        const sharedSecret = await computeSharedSecret(myKeyPair.privateKey, peerPublicKey);
        await ratchet.init(sharedSecret);

        uiConnStatusText.innerText = "Secured (AES-256)";
        uiStatus.innerHTML = '<i class="fas fa-lock" style="font-size:10px;"></i> Secured Connection';
        uiInput.disabled = false;
        uiBtn.disabled = false;
        updateDebugUI();
    } catch (e) {
        console.error("Handshake Error:", e);
    }
});

// 4. Typing
uiInput.addEventListener('input', () => {
    socket.emit('typing', true);
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => socket.emit('typing', false), 2000);
});

socket.on('typing', (isTyping) => {
    if(isTyping) {
        uiStatus.innerText = "typing...";
        uiStatus.style.color = "#00a884";
    } else {
        uiStatus.innerHTML = '<i class="fas fa-lock" style="font-size:10px;"></i> Secured Connection';
        uiStatus.style.color = "#8696a0";
    }
});

// 5. Incoming Message
socket.on('secure-msg', async (data) => {
    if (data.sender === socket.id) return;
    uiStatus.innerHTML = '<i class="fas fa-lock" style="font-size:10px;"></i> Secured Connection';
    uiStatus.style.color = "#8696a0";

    logNetworkTraffic("INCOMING", data);
    
    try {
        const sessionKey = await ratchet.ratchetForward();
        updateDebugUI();
        const plainText = await decryptWithSessionKey(sessionKey, data.ciphertext, data.iv);
        appendMessage("Peer", plainText, "peer");
    } catch (err) {
        console.error(err);
        appendMessage("System", "Decryption Failed", "system");
    }
});

// 6. Sending Message
uiBtn.addEventListener('click', sendMessage);
uiInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendMessage(); });

async function sendMessage() {
    const text = uiInput.value;
    if (!text) return;
    try {
        const sessionKey = await ratchet.ratchetForward();
        updateDebugUI();
        const encrypted = await encryptWithSessionKey(sessionKey, text);

        const payload = {
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv, // IV is already Base64 from crypto-primitives
            sender: socket.id
        };
        
        logNetworkTraffic("OUTGOING", payload);
        socket.emit('secure-msg', payload);
        appendMessage("You", text, "self");
        uiInput.value = "";
    } catch (err) {
        alert("Encryption Failed: " + err.message);
    }
}

// Helpers
async function broadcastHandshake() {
    if (!myKeyPair) return;
    const k = await exportKey(myKeyPair.publicKey);
    socket.emit('signal-handshake', { publicKey: k });
}

async function updateDebugUI() {
    // Show FULL Hex Session Key
    uiSessionKey.innerText = await ratchet.getFingerprint();
    uiSessionKey.style.color = "#00a884";
    setTimeout(() => uiSessionKey.style.color = "#00ff9d", 500);
}

function appendMessage(sender, text, type) {
    const div = document.createElement('div');
    div.className = `msg ${type}`;
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const checks = type === 'self' ? '<i class="fas fa-check-double" style="color:#53bdeb"></i>' : '';
    div.innerHTML = `${text}<div class="msg-meta">${time} ${checks}</div>`;
    uiChat.appendChild(div);
    uiChat.scrollTop = uiChat.scrollHeight;
}

function logNetworkTraffic(dir, data) {
    const div = document.createElement('div');
    const color = dir === "OUTGOING" ? "#00a884" : "#ff5f5f";
    
    // 1. Decode Base64 to get raw bytes
    const rawString = atob(data.ciphertext);
    const len = rawString.length;
    
    // 2. The Tag is ALWAYS the last 16 bytes in WebCrypto AES-GCM
    const tagBytes = rawString.slice(len - 16);
    const cipherBytes = rawString.slice(0, len - 16);
    
    // 3. Re-encode to Base64 for display
    const tagB64 = btoa(tagBytes);
    const cipherB64 = btoa(cipherBytes);

    div.innerHTML = `
        <span style="color:${color}; font-weight:bold;">[${dir}]</span><br>
        <span style="color:#aaa">IV:</span> ${data.iv}<br>
        <span style="color:#aaa">Cipher:</span> ${cipherB64}<br>
        <span style="color:#ff5f5f">Tag:</span> ${tagB64}
    `;
    div.className = "log-entry";
    uiNetwork.prepend(div);
}