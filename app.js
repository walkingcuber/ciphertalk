console.log("🚀 成功載入 v2.3 最新版代碼！"); // 可以在 F12 開發者工具的主控台看到這行

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getFirestore, doc, setDoc, getDoc, collection, addDoc, query, getDocs, onSnapshot, orderBy } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";

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
let currentPrivateKey = ""; 
let activeTargetUser = ""; 
let unsubscribeChat = null;

const forgeObj = window.forge;

// =================密碼學晶片工具=================
function generateKeyPair() {
    const rsa = forgeObj.pki.rsa;
    const keypair = rsa.generateKeyPair({bits: 2048, e: 0x10001});
    return {
        privateKeyPem: forgeObj.pki.privateKeyToPem(keypair.privateKey),
        publicKeyPem: forgeObj.pki.publicKeyToPem(keypair.publicKey)
    };
}

function encryptPrivateKeyWithPassword(privateKeyPem, password) {
    const salt = forgeObj.random.getBytesSync(8);
    const key = forgeObj.pkcs5.pbkdf2(password, salt, 1000, 16);
    const iv = forgeObj.random.getBytesSync(16);
    const cipher = forgeObj.cipher.createCipher('AES-CBC', key);
    cipher.start({iv: iv});
    cipher.update(forgeObj.util.createBuffer(forgeObj.util.encodeUtf8(privateKeyPem)));
    cipher.finish();
    return JSON.stringify({
        salt: forgeObj.util.bytesToHex(salt),
        iv: forgeObj.util.bytesToHex(iv),
        ct: cipher.output.toHex()
    });
}

function decryptPrivateKeyWithPassword(encryptedJsonStr, password) {
    const data = JSON.parse(encryptedJsonStr);
    const salt = forgeObj.util.hexToBytes(data.salt);
    const iv = forgeObj.util.hexToBytes(data.iv);
    const ct = forgeObj.util.hexToBytes(data.ct);
    const key = forgeObj.pkcs5.pbkdf2(password, salt, 1000, 16);
    const decipher = forgeObj.cipher.createDecipher('AES-CBC', key);
    decipher.start({iv: iv});
    decipher.update(forgeObj.util.createBuffer(ct));
    if(!decipher.finish()) throw new Error("密碼錯誤，金鑰解鎖失敗！");
    return forgeObj.util.decodeUtf8(decipher.output.getBytes());
}

function encryptRSA(text, publicKeyPem) {
    const publicKey = forgeObj.pki.publicKeyFromPem(publicKeyPem);
    const encrypted = publicKey.encrypt(forgeObj.util.encodeUtf8(text), 'RSA-OAEP', {
        md: forgeObj.md.sha256.create(), mgf1: { md: forgeObj.md.sha256.create() }
    });
    return forgeObj.util.encode64(encrypted);
}

function decryptRSA(cryptoB64, privateKeyPem) {
    const privateKey = forgeObj.pki.privateKeyFromPem(privateKeyPem);
    const encryptedBytes = forgeObj.util.decode64(cryptoB64);
    const decrypted = privateKey.decrypt(encryptedBytes, 'RSA-OAEP', {
        md: forgeObj.md.sha256.create(), mgf1: { md: forgeObj.md.sha256.create() }
    });
    return forgeObj.util.decodeUtf8(decrypted);
}

// =================系統核心功能=================

document.getElementById('btnRegister').addEventListener('click', async () => {
    const email = document.getElementById('regEmail').value.trim().toLowerCase();
    const password = document.getElementById('regPassword').value;
    if (!email || !password) return alert('請填寫註冊 Email 與密碼！');
    
    document.getElementById('btnRegister').innerText = "安全金鑰部署中...";
    setTimeout(async () => {
        try {
            const { privateKeyPem, publicKeyPem } = generateKeyPair();
            const lockedPrivateKey = encryptPrivateKeyWithPassword(privateKeyPem, password);
            
            await setDoc(doc(dbKeyVault, "users", email), {
                email: email,
                public_key: publicKeyPem,
                encrypted_private_key: lockedPrivateKey,
                created_at: Date.now()
            });
            
            alert('🎉 註冊成功！金鑰已自動安全託管。現在可以使用密碼登入囉！');
            document.getElementById('regEmail').value = "";
            document.getElementById('regPassword').value = "";
        } catch (e) { alert('註冊失敗: ' + e.message); }
        finally { document.getElementById('btnRegister').innerText = "完成註冊 (自動託管金鑰)"; }
    }, 200);
});

// 登入按鈕監聽
document.getElementById('btnLogin').addEventListener('click', async () => {
    const email = document.getElementById('loginEmail').value.trim().toLowerCase();
    const password = document.getElementById('loginPassword').value;
    if (!email || !password) return alert('請輸入登入 Email 與密碼！');

    try {
        const userSnap = await getDoc(doc(dbKeyVault, "users", email));
        if (!userSnap.exists()) return alert('❌ 找不到此帳號，請先在上方註冊！');
        
        const userData = userSnap.data();
        const encryptedPrivateKeyFromCloud = userData.encrypted_private_key;
        
        currentPrivateKey = decryptPrivateKeyWithPassword(encryptedPrivateKeyFromCloud, password);
        currentUser = email;
        
        // 1. 修改狀態文字與顏色
        const lblStatus = document.getElementById('lblMyStatus');
        lblStatus.innerText = `🟢 在線: ${currentUser}`;
        lblStatus.style.color = "#4ade80"; 
        
        // 2. 隱藏登入面板，顯示登出按鈕
        const authSection = document.getElementById('authSection');
        if (authSection) {
            authSection.style.display = 'none';
        }
        const btnLogout = document.getElementById('btnLogout');
        if (btnLogout) {
            btnLogout.style.display = 'block';
        }
        
        // 3. 清空輸入框
        document.getElementById('loginEmail').value = "";
        document.getElementById('loginPassword').value = "";

        // 4. 載入聯絡人
        loadFriendList();
    } catch (e) { alert('登入失敗: 密碼錯誤或網路異常'); }
});

// 登出功能
document.getElementById('btnLogout').addEventListener('click', () => {
    currentUser = "";
    currentPrivateKey = "";
    activeTargetUser = "";
    if (unsubscribeChat) {
        unsubscribeChat();
        unsubscribeChat = null;
    }
    
    document.getElementById('lblMyStatus').innerText = "🔴 請先註冊或登入";
    document.getElementById('lblMyStatus').style.color = "#cbd5e1";
    
    const authSection = document.getElementById('authSection');
    if (authSection) authSection.style.display = 'flex';
    
    const btnLogout = document.getElementById('btnLogout');
    if (btnLogout) btnLogout.style.display = 'none';
    
    document.getElementById('friendList').innerHTML = "<div style='text-align:center; color:#8e8e93; font-size:12px; margin-top:20px;'>請先登入以載入朋友名單</div>";
    document.getElementById('chatTitle').innerText = "💬 請選擇左側聯絡人開始聊天";
    document.getElementById('chatHistory').innerHTML = "<div style='text-align: center; color: #8e8e93; margin-top: 50px; font-size: 14px;'>沒有選取的對話</div>";
    
    document.getElementById('msgContent').disabled = true;
    document.getElementById('btnSend').disabled = true;
});

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

function openChatWith(targetEmail) {
    activeTargetUser = targetEmail;
    document.getElementById('chatTitle').innerText = `💬 與 ${targetEmail} 通訊中`;
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
                    const cipherToDecrypt = isMySent ? msg.encrypted_for_sender : msg.encrypted_for_receiver;
                    displayText = decryptRSA(cipherToDecrypt, currentPrivateKey);
                } catch (err) { displayText = "❌ 密文解密失敗"; }
                
                chatHistory.innerHTML += `<div class="${rowClass}"><div class="bubble">${displayText}</div></div>`;
            }
        });
        chatHistory.scrollTop = chatHistory.scrollHeight;
    });
}

async function sendMessage() {
    const msgInput = document.getElementById('msgContent');
    const msg = msgInput.value;
    if (!msg || !activeTargetUser) return;
    
    try {
        const [targetSnap, meSnap] = await Promise.all([
            getDoc(doc(dbKeyVault, "users", activeTargetUser)),
            getDoc(doc(dbKeyVault, "users", currentUser))
        ]);
        
        if (!targetSnap.exists() || !meSnap.exists()) return alert('獲取加密金鑰失敗！');
        
        const targetPubKey = targetSnap.data().public_key;
        const myPubKey = meSnap.data().public_key;
        
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
document.getElementById('msgContent').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        sendMessage();
    }
});
