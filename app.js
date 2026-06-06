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
let currentPrivateKey = "";
let activeTargetUser = ""; 
let unsubscribeChat = null; // 用來清除舊對話的即時監聽器

// RSA 加解密演算
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

// 註冊帳號
document.getElementById('btnRegister').addEventListener('click', async () => {
    const email = document.getElementById('myEmail').value.trim().toLowerCase();
    if (!email) return alert('請輸入 Email！');
    document.getElementById('btnRegister').innerText = "註冊中...";
    setTimeout(async () => {
        try {
            const { privateKeyPem, publicKeyPem } = generateKeyPair();
            await setDoc(doc(dbKeyVault, "users", email), { email: email, public_key: publicKeyPem, created_at: Date.now() });
            document.getElementById('txtPrivateKey').value = privateKeyPem;
            document.getElementById('inputPrivateKey').value = privateKeyPem;
            document.getElementById('keyBox').style.display = 'block';
            alert('✅ 註冊成功！公鑰已上傳，請立刻複製下方黃框私鑰備份，並點擊下方登入！');
        } catch (e) { alert('註冊失敗: ' + e.message); }
        finally { document.getElementById('btnRegister').innerText = "✨ 註冊新帳號"; }
    }, 200);
});

// 登入並同步朋友清單
document.getElementById('btnLogin').addEventListener('click', async () => {
    const email = document.getElementById('myEmail').value.trim().toLowerCase();
    const privKey = document.getElementById('inputPrivateKey').value.trim();
    if (!email || !privKey) return alert('請填寫 Email 與貼上私鑰！');

    currentUser = email;
    currentPrivateKey = privKey;
    document.getElementById('lblMyStatus').innerText = `🟢 在線: ${currentUser}`;
    
    // 載入好友名單 (撈取專案 A 所有註冊的人)
    loadFriendList();
});

// 撈取資料庫內的所有使用者，做成朋友名單
async function loadFriendList() {
    const friendListContainer = document.getElementById('friendList');
    friendListContainer.innerHTML = "<div style='text-align:center; font-size:12px; color:#8e8e93;'>載入聯絡人中...</div>";
    
    try {
        const querySnapshot = await getDocs(collection(dbKeyVault, "users"));
        friendListContainer.innerHTML = "";
        
        querySnapshot.forEach((doc) => {
            const userData = doc.data();
            if (userData.email === currentUser) return; // 不把自己放在名單中
            
            const firstLetter = userData.email.charAt(0).toUpperCase();
            const item = document.createElement('div');
            item.className = 'friend-item';
            item.innerHTML = `
                <div class="friend-avatar">${firstLetter}</div>
                <div class="friend-info"><div>${userData.email}</div></div>
            `;
            
            // 點選聯絡人切換對話視窗
            item.addEventListener('click', () => {
                document.querySelectorAll('.friend-item').forEach(el => el.classList.remove('active'));
                item.classList.add('active');
                openChatWith(userData.email);
            });
            friendListContainer.appendChild(item);
        });
        if(friendListContainer.innerHTML === "") {
            friendListContainer.innerHTML = "<div style='text-align:center; font-size:12px; color:#8e8e93;'>目前沒有其他使用者。</div>";
        }
    } catch(e) { alert("好友名單載入失敗: " + e.message); }
}

// 開啟並「即時監聽同步」與特定朋友的對話
function openChatWith(targetEmail) {
    activeTargetUser = targetEmail;
    document.getElementById('chatTitle').innerText = `💬 與 ${targetEmail} 加密通訊中`;
    document.getElementById('msgContent').disabled = false;
    document.getElementById('btnSend').disabled = false;
    
    // 如果之前有監聽別人的對話，先斷開連線
    if (unsubscribeChat) unsubscribeChat();
    
    const chatHistory = document.getElementById('chatHistory');
    chatHistory.innerHTML = "<div style='text-align:center; color:#8e8e93;'>🔒 開啟端到端安全通道...</div>";
    
    // 監聽傳輸庫(專案 B) 裡，所有我跟對方的對話紀錄
    const q = query(collection(dbMessenger, "messages"), orderBy("timestamp", "asc"));
    
    unsubscribeChat = onSnapshot(q, (snapshot) => {
        chatHistory.innerHTML = "";
        let hasMessage = false;
        
        snapshot.forEach((doc) => {
            const msg = doc.data();
            
            // 篩選出「我傳給對方」或「對方傳給我」的訊息
            const isMySent = (msg.sender_email === currentUser && msg.receiver_email === activeTargetUser);
            const isMyReceived = (msg.sender_email === activeTargetUser && msg.receiver_email === currentUser);
            
            if (isMySent || isMyReceived) {
                hasMessage = true;
                const rowClass = isMySent ? 'msg-row me' : 'msg-row other';
                let displayText = "";
                
                try {
                    // 關鍵：如果是自己傳的，解密針對自己公鑰加密的欄位；如果是別人傳的，解密針對自己加密的欄位
                    // 為了架構簡單安全，發送端發信時會生成兩份密文（一份用對方公鑰加密，一份用自己公鑰加密）
                    const cipherToDecrypt = isMySent ? msg.encrypted_for_sender : msg.encrypted_for_receiver;
                    displayText = decryptRSA(cipherToDecrypt, currentPrivateKey);
                } catch (err) {
                    displayText = "❌ 密文解密失敗 (金鑰不對)";
                }
                
                chatHistory.innerHTML += `
                    <div class="${rowClass}">
                        <div class="bubble ${displayText.startsWith('❌') ? 'error-bubble' : ''}">${displayText}</div>
                    </div>`;
            }
        });
        
        if (!hasMessage) {
            chatHistory.innerHTML = "<div style='text-align:center; color:#8e8e93; font-size:13px;'>沒有歷史訊息，輸入下方訊息開始聊天！</div>";
        }
        chatHistory.scrollTop = chatHistory.scrollHeight; // 自動滾動到最底
    });
}

// 發送訊息（同步雙向加密技術）
document.getElementById('btnSend').addEventListener('click', async () => {
    const msg = document.getElementById('msgContent').value;
    if (!msg || !activeTargetUser) return;
    
    try {
        // 1. 去專案 A 撈取「對方」和「自己」的公鑰
        const targetUserDoc = await getDocs(query(collection(dbKeyVault, "users"), where("email", "==", activeTargetUser)));
        const meUserDoc = await getDocs(query(collection(dbKeyVault, "users"), where("email", "==", currentUser)));
        
        let targetPubKey = "";
        let myPubKey = "";
        
        targetUserDoc.forEach(d => targetPubKey = d.data().public_key);
        meUserDoc.forEach(d => myPubKey = d.data().public_key);
        
        if (!targetPubKey) return alert('找不到對方的公鑰！');
        
        // 2. 用對方的公鑰加密（給對方看）
        const encryptedForReceiver = encryptRSA(msg, targetPubKey);
        // 3. 用自己的公鑰加密（留給自己看，這樣自己才知道發了什麼！）
        const encryptedForSender = encryptRSA(msg, myPubKey);
        
        // 4. 把雙密文包裹送入傳輸庫(專案 B)
        await addDoc(collection(dbMessenger, "messages"), {
            sender_email: currentUser,
            receiver_email: activeTargetUser,
            encrypted_for_receiver: encryptedForReceiver, // 給接收方解密的密文
            encrypted_for_sender: encryptedForSender,     // 給發送方解密的密文
            timestamp: Date.now()
        });
        
        document.getElementById('msgContent').value = "";
    } catch (e) { alert('發送失敗: ' + e.message); }
});
