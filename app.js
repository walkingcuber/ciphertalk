import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getFirestore, doc, setDoc, collection, addDoc, query, where, getDocs, orderBy } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";
import "https://cdnjs.cloudflare.com/ajax/libs/forge/0.10.0/forge.min.js";

// ===================================================
// 🔑 專案 A 設定：管理「公鑰」的專案（私）
// ===================================================
const configKeyVault = {
    apiKey: "AIzaSyBK86_OZuKQbIRjZBFNXv1iNmS9yHgPks8",
    authDomain: "ciphertalk-keyvault.firebaseapp.com",
    databaseURL: "https://ciphertalk-keyvault-default-rtdb.firebaseio.com",
    projectId: "ciphertalk-keyvault",
    storageBucket: "ciphertalk-keyvault.firebasestorage.app",
    messagingSenderId: "510292113634",
    appId: "1:510292113634:web:8bde2742246de3e40746bb"
};

// ===================================================
// 💬 專案 B 設定：做「訊息傳輸」的專案（訊）
// ===================================================
const configMessenger = {
    apiKey: "AIzaSyA0Tn8AKO4XlQOfFSoeq-Mdbkb45j32os0",
    authDomain: "ciphertalk-messenger.firebaseapp.com",
    projectId: "ciphertalk-messenger",
    storageBucket: "ciphertalk-messenger.firebasestorage.app",
    messagingSenderId: "1095049485231",
    appId: "1:1095049485231:web:51220bc48d9761138c6d5a"
};

// 初始化 Firebase
const appKeyVault = initializeApp(configKeyVault, "KeyVaultInstance");
const appMessenger = initializeApp(configMessenger, "MessengerInstance");
const dbKeyVault = getFirestore(appKeyVault);   
const dbMessenger = getFirestore(appMessenger); 

// RSA 密碼學晶片
function generateKeyPair() {
    const rsa = forge.pki.rsa;
    const keypair = rsa.generateKeyPair({bits: 2048, e: 0x10001});
    return {
        privateKeyPem: forge.pki.privateKeyToPem(keypair.privateKey),
        publicKeyPem: forge.pki.publicKeyToPem(keypair.publicKey)
    };
}
function encryptRSA(text, publicKeyPem) {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const encrypted = publicKey.encrypt(forge.util.encodeUtf8(text), 'RSA-OAEP', {
        md: forge.md.sha256.create(), mgf1: { md: forge.md.sha256.create() }
    });
    return forge.util.encode64(encrypted);
}
function decryptRSA(cryptoB64, privateKeyPem) {
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const encryptedBytes = forge.util.decode64(cryptoB64);
    const decrypted = privateKey.decrypt(encryptedBytes, 'RSA-OAEP', {
        md: forge.md.sha256.create(), mgf1: { md: forge.md.sha256.create() }
    });
    return forge.util.decodeUtf8(decrypted);
}

// 介面更新：同步狀態欄
function updateStatusHeader(email) {
    document.getElementById('lblMyStatus').innerText = `🟢 已連線身分: ${email}`;
}

// 功能 1：註冊帳號
document.getElementById('btnRegister').addEventListener('click', async () => {
    const email = document.getElementById('myEmail').value.trim().toLowerCase();
    if (!email) return alert('請輸入 Email！');
    
    document.getElementById('btnRegister').innerText = "生成中...";
    setTimeout(async () => {
        try {
            const { privateKeyPem, publicKeyPem } = generateKeyPair();
            await setDoc(doc(dbKeyVault, "users", email), { email: email, public_key: publicKeyPem, created_at: Date.now() });
            
            document.getElementById('txtPrivateKey').value = privateKeyPem;
            document.getElementById('inputPrivateKey').value = privateKeyPem;
            document.getElementById('keyBox').style.display = 'block';
            updateStatusHeader(email);
            alert('✅ 註冊成功！公鑰已傳上雲端，請複製備份黃框私鑰！');
        } catch (e) { alert('註冊失敗: ' + e.message); }
        finally { document.getElementById('btnRegister').innerText = "✨ 註冊新帳號"; }
    }, 200);
});

// 功能 2：加密並發送訊息
document.getElementById('btnSend').addEventListener('click', async () => {
    const myEmail = document.getElementById('myEmail').value.trim().toLowerCase();
    const targetEmail = document.getElementById('targetEmail').value.trim().toLowerCase();
    const msg = document.getElementById('msgContent').value;
    
    if (!myEmail || !targetEmail || !msg) return alert('發送失敗：請確認我的Email、對方Email、訊息內容皆已填寫！');
    
    try {
        const targetUserDoc = await getDocs(query(collection(dbKeyVault, "users"), where("email", "==", targetEmail)));
        if (targetUserDoc.empty) return alert('❌ 雲端找不到對方的公鑰，請確認對方註冊過！');
        
        let targetPubKey = "";
        targetUserDoc.forEach(d => targetPubKey = d.data().public_key);
        
        const encryptedMsg = encryptRSA(msg, targetPubKey);
        
        await addDoc(collection(dbMessenger, "messages"), {
            sender_email: myEmail,
            receiver_email: targetEmail,
            encrypted_text: encryptedMsg,
            timestamp: Date.now()
        });
        
        document.getElementById('msgContent').value = "";
        alert('🚀 訊息已加密送達！');
        // 自動刷新聊天紀錄
        document.getElementById('btnFetch').click();
    } catch (e) { alert('傳輸失敗: ' + e.message); }
});

// 功能 3：拉取全通訊紀錄並在前端進行「氣泡化解密」
document.getElementById('btnFetch').addEventListener('click', async () => {
    const myEmail = document.getElementById('myEmail').value.trim().toLowerCase();
    const privateKeyPem = document.getElementById('inputPrivateKey').value.trim();
    
    if (!myEmail || !privateKeyPem) return alert('請先輸入我的 Email 並配置正確的私鑰！');
    updateStatusHeader(myEmail);
    
    const chatContainer = document.getElementById('chatHistory');
    chatContainer.innerHTML = "<div style='text-align:center; color:#94a3b8;'>📥 正在同步雲端安全訊息...</div>";
    
    try {
        // 同時撈取「我收到的」和「我發出的」訊息，才能組成聊天室
        const qReceived = query(collection(dbMessenger, "messages"), where("receiver_email", "==", myEmail));
        const qSent = query(collection(dbMessenger, "messages"), where("sender_email", "==", myEmail));
        
        const [snapReceived, snapSent] = await Promise.all([getDocs(qReceived), getDocs(qSent)]);
        
        let allMessages = [];
        snapReceived.forEach(doc => allMessages.push({ id: doc.id, ...doc.data(), type: 'other' }));
        snapSent.forEach(doc => allMessages.push({ id: doc.id, ...doc.data(), type: 'me' }));
        
        // 依時間排序
        allMessages.sort((a, b) => a.timestamp - b.timestamp);
        
        chatContainer.innerHTML = "";
        if (allMessages.length === 0) {
            chatContainer.innerHTML = "<div style='text-align:center; color:#94a3b8; font-size:13px;'>目前沒有通訊紀錄。</div>";
            return;
        }
        
        allMessages.forEach((msg) => {
            if (msg.type === 'me') {
                // 自己發出去的，雖然雲端上是密文，但因發送端通常不存私鑰解密，為了測試方便，我們在前端如果是 "me" 且解不開時，可以直接提示「已安全發送（密文狀態）」
                chatContainer.innerHTML += `
                    <div class="msg-wrapper me">
                        <span class="sender-name">我 發給 ${msg.receiver_email}</span>
                        <div class="bubble">🔒 [已加密發送]</div>
                    </div>`;
            } else {
                // 別人傳給我的，使用我的私鑰解密
                try {
                    const decryptedText = decryptRSA(msg.encrypted_text, privateKeyPem);
                    chatContainer.innerHTML += `
                        <div class="msg-wrapper other">
                            <span class="sender-name">${msg.sender_email}</span>
                            <div class="bubble">${decryptedText}</div>
                        </div>`;
                } catch (err) {
                    chatContainer.innerHTML += `
                        <div class="msg-wrapper other">
                            <span class="sender-name">${msg.sender_email}</span>
                            <div class="bubble error-bubble">❌ 密文解密失敗 (私鑰不符)</div>
                        </div>`;
                }
            }
        });
        
        // 自動捲動到最底
        chatContainer.scrollTop = chatContainer.scrollHeight;
        
    } catch (e) { alert('同步失敗: ' + e.message); }
});