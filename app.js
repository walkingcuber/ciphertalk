import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getFirestore, doc, setDoc, collection, addDoc, query, where, getDocs, onSnapshot, orderBy } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";
import "https://cdnjs.cloudflare.com/ajax/libs/forge/0.10.0/forge.min.js";

const configKeyVault = {
    apiKey: "AIzaSyBK86_OZuKQbIRjZBFNXv1iNmS9yHgPks8",
    authDomain: "ciphertalk-keyvault.firebaseapp.com",
    databaseURL: "https://ciphertalk-keyvault-default-rtdb.firebaseio.com",
    projectId: "ciphertalk-keyvault",
    storageBucket: "ciphertalk-keyvault.firebasestorage.app",
    messagingSenderId: "510292113634",
    appId: "1:510292113634:web:8bde2742246de3e40746bb"
};

const configMessenger = {
    apiKey: "AIzaSyA0Tn8AKO4XlQOfFSoeq-Mdbkb45j32os0",
    authDomain: "ciphertalk-messenger.firebaseapp.com",
    projectId: "ciphertalk-messenger",
    storageBucket: "ciphertalk-messenger.firebasestorage.app",
    messagingSenderId: "1095049485231",
    appId: "1:1095049485231:web:51220bc48d9761138c6d5a"
};

const appKeyVault = initializeApp(configKeyVault, "KeyVaultInstance");
const appMessenger = initializeApp(configMessenger, "MessengerInstance");
const dbKeyVault = getFirestore(appKeyVault);   
const dbMessenger = getFirestore(appMessenger); 

let currentUser = "";
let currentPrivateKey = ""; // 🗝️ 密碼解鎖後會直接存於此變數中（API自動讀取，不需人腦記憶）
let activeTargetUser = ""; 
let unsubscribeChat = null;

// =================密碼學晶片工具=================
function generateKeyPair() {
    const rsa = forge.pki.rsa;
    const keypair = rsa.generateKeyPair({bits: 2048, e: 0x10001});
    return {
        privateKeyPem: forge.pki.privateKeyToPem(keypair.privateKey),
        publicKeyPem: forge.pki.publicKeyToPem(keypair.publicKey)
    };
}
// 使用密碼加密私鑰（AES-CBC 演算法）
function encryptPrivateKeyWithPassword(privateKeyPem, password) {
    const salt = forge.random.getBytesSync(8);
    const key = forge.pkcs5.pbkdf2(password, salt, 1000, 16);
    const iv = forge.random.getBytesSync(16);
    const cipher = forge.cipher.createCipher('AES-CBC', key);
    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(privateKeyPem)));
    cipher.finish();
    return JSON.stringify({
        salt: forge.util.bytesToHex(salt),
        iv: forge.util.bytesToHex(iv),
        ct: cipher.output.toHex()
    });
}
// 使用密碼解密私鑰
function decryptPrivateKeyWithPassword(encryptedJsonStr, password) {
    const data = JSON.parse(encryptedJsonStr);
    const salt = forge.util.hexToBytes(data.salt);
    const iv = forge.util.hexToBytes(data.iv);
    const ct = forge.util.hexToBytes(data.ct);
    const key = forge.pkcs5.pbkdf2(password, salt, 1000, 16);
    const decipher = forge.cipher.createDecipher('AES-CBC', key);
    decipher.start({iv: iv});
    decipher.update(forge.util.createBuffer(ct));
    if(!decipher.finish()) throw new Error("密碼錯誤，金鑰解鎖失敗！");
    return forge.util.decodeUtf8(decipher.output.getBytes());
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

// =================系統核心功能=================

// 1. 註冊帳號：生成 RSA，並用「密碼」鎖住私鑰後一起存到雲端
document.getElementById('btnRegister').addEventListener('click', async () => {
    const email = document.getElementById('regEmail').value.trim().toLowerCase();
    const password = document.getElementById('regPassword').value;
    if (!email || !password) return alert('請填寫註冊 Email 與密碼！');
    
    document.getElementById('btnRegister').innerText = "安全金鑰部署中...";
    setTimeout(async () => {
        try {
            const { privateKeyPem, publicKeyPem } = generateKeyPair();
            // 用密碼把私鑰鎖起來
            const lockedPrivateKey = encryptPrivateKeyWithPassword(privateKeyPem, password);
            
            // 將公鑰與「被鎖住的私鑰」一起推上專案 A
            await setDoc(doc(dbKeyVault, "users", email), {
                email: email,
                public_key: publicKeyPem,
                encrypted_private_key: lockedPrivateKey,
                created_at: Date.now()
            });
            
            alert('🎉 註冊成功！金鑰已自動安全託管。現在您可以使用下方的密碼登入功能囉！');
            document.getElementById('regEmail').value = "";
            document.getElementById('regPassword').value = "";
        } catch (e) { alert('註冊失敗: ' + e.message); }
        finally { document.getElementById('btnRegister').innerText = "完成註冊 (自動託管金鑰)"; }
    }, 200);
});

// 2. 密碼登入：自動去雲端抓取「加密私鑰」，並用密碼當場解開，自動填入系統變數！
document.getElementById('btnLogin').addEventListener('click', async () => {
    const email = document.getElementById('loginEmail').value.trim().toLowerCase();
    const password = document.getElementById('loginPassword').value;
    if (!email || !password) return alert('請輸入登入 Email 與密碼！');

    try {
        const userDoc = await getDocs(query(collection(dbKeyVault, "users"), where("email", "==", email)));
        if (userDoc.empty) return alert('❌ 找不到此帳號，請先在上方註冊！');
        
        let encryptedPrivateKeyFromCloud = "";
        userDoc.forEach(d => encryptedPrivateKeyFromCloud = d.data().encrypted_private_key);
        
        // 自動解鎖私鑰並填入系統
        currentPrivateKey = decryptPrivateKeyWithPassword(encryptedPrivateKeyFromCloud, password);
        currentUser = email;
        
        document.getElementById('lblMyStatus').innerText = `🟢 在線: ${currentUser}`;
        alert('🔑 密碼驗證成功，私鑰已自動解鎖填入背後 API！');
        loadFriendList();
    } catch (e) { alert('登入失敗: ' + e.message); }
});

// 3. 載入好友名單
async function loadFriendList() {
    const friendListContainer = document.getElementById('friendList');
    friendListContainer.innerHTML = "載入聯絡人中...";
    try {
        const querySnapshot = await getDocs(collection(dbKeyVault, "users"));
        friendListContainer.innerHTML = "";
        querySnapshot.forEach((doc) => {
            const userData = doc.data();
            if (userData.email === currentUser) return;
            const firstLetter = userData.email.charAt(0).toUpperCase();
            const item = document.createElement('div');
            item.className = 'friend-item';
            item.innerHTML = `<div class="friend-avatar">${firstLetter}</div><div class="friend-info"><div>${userData.email}</div></div>`;
            item.addEventListener('click', () => {
                document.querySelectorAll('.friend-item').forEach(el => el.classList.remove('active'));
                item.classList.add('active');
                openChatWith(userData.email);
            });
            friendListContainer.appendChild(item);
        });
    } catch(e) { console.error(e); }
}

// 4. 即時同步聊天室
function openChatWith(targetEmail) {
    activeTargetUser = targetEmail;
    document.getElementById('chatTitle').innerText = `💬 與 ${targetEmail} 通訊中 (金鑰已自動就位)`;
    document.getElementById('msgContent').disabled = false;
    document.getElementById('btnSend').disabled = false;
    if (unsubscribeChat) unsubscribeChat();
    
    const chatHistory = document.getElementById('chatHistory');
    const q = query(collection(dbMessenger, "messages"), orderBy("timestamp", "asc"));
    
    unsubscribeChat = onSnapshot(q, (snapshot) => {
        chatHistory.innerHTML = "";
        snapshot.forEach((doc) => {
            const msg = doc.data();
            const isMySent = (msg.sender_email === currentUser && msg.receiver_email === activeTargetUser);
            const isMyReceived = (msg.sender_email === activeTargetUser && msg.receiver_email === currentUser);
            
            if (isMySent || isMyReceived) {
                const rowClass = isMySent ? 'msg-row me' : 'msg-row other';
                let displayText = "";
                try {
                    // 自動使用解密變數進行對話翻譯
                    const cipherToDecrypt = isMySent ? msg.encrypted_for_sender : msg.encrypted_for_receiver;
                    displayText = decryptRSA(cipherToDecrypt, currentPrivateKey);
                } catch (err) { displayText = "❌ 密文解密失敗"; }
                
                chatHistory.innerHTML += `<div class="${rowClass}"><div class="bubble">${displayText}</div></div>`;
            }
        });
        chatHistory.scrollTop = chatHistory.scrollHeight;
    });
}

// 5. 發送訊息核心 (綁定點擊按鈕與按 Enter 鍵)
async function sendMessage() {
    const msgInput = document.getElementById('msgContent');
    const msg = msgInput.value;
    if (!msg || !activeTargetUser) return;
    
    try {
        const targetUserDoc = await getDocs(query(collection(dbKeyVault, "users"), where("email", "==", activeTargetUser)));
        const meUserDoc = await getDocs(query(collection(dbKeyVault, "users"), where("email", "==", currentUser)));
        let targetPubKey = "", myPubKey = "";
        targetUserDoc.forEach(d => targetPubKey = d.data().public_key);
        meUserDoc.forEach(d => myPubKey = d.data().public_key);
        
        const encryptedForReceiver = encryptRSA(msg, targetPubKey);
        const encryptedForSender = encryptRSA(msg, myPubKey);
        
        await addDoc(collection(dbMessenger, "messages"), {
            sender_email: currentUser,
            receiver_email: activeTargetUser,
            encrypted_for_receiver: encryptedForReceiver,
            encrypted_for_sender: encryptedForSender,
            timestamp: Date.now()
        });
        msgInput.value = "";
    } catch (e) { alert('發送失敗: ' + e.message); }
}

document.getElementById('btnSend').addEventListener('click', sendMessage);
// 💡 自動監聽 Enter 鍵，按下去立刻執行發送 API！
document.getElementById('msgContent').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        sendMessage();
    }
});
