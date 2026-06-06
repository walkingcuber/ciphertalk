import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getFirestore, doc, setDoc, collection, addDoc, query, where, getDocs } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";
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
    appId: "1:510292113634:web:8bde2742246de3e40746bb",
    measurementId: "G-48KLMFFN8G"
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
    appId: "1:1095049485231:web:51220bc48d9761138c6d5a",
    measurementId: "G-Y0MXLC2Q8X"
};

// 初始化 2 個 Firebase 實例
const appKeyVault = initializeApp(configKeyVault, "KeyVaultInstance");
const appMessenger = initializeApp(configMessenger, "MessengerInstance");
const dbKeyVault = getFirestore(appKeyVault);   
const dbMessenger = getFirestore(appMessenger); 

// RSA 演算法
function generateKeyPair() {
    const rsa = forge.pki.rsa;
    const keypair = rsa.generateKeyPair({bits: 2048, e: 0x10001});
    const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
    const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
    return { privateKeyPem, publicKeyPem };
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

// 功能 1：上傳公鑰至專案 A
document.getElementById('btnRegister').addEventListener('click', async () => {
    const email = document.getElementById('myEmail').value.trim().toLowerCase();
    if (!email) return alert('請輸入 Email！');
    document.getElementById('btnRegister').innerText = "🔑 金鑰生成中...";
    setTimeout(async () => {
        try {
            const { privateKeyPem, publicKeyPem } = generateKeyPair();
            await setDoc(doc(dbKeyVault, "users", email), { email: email, public_key: publicKeyPem, created_at: Date.now() });
            document.getElementById('txtPrivateKey').value = privateKeyPem;
            document.getElementById('inputPrivateKey').value = privateKeyPem;
            document.getElementById('keyBox').style.display = 'block';
            alert('✅ 成功！公鑰已匯入密鑰專案。請備份私鑰！');
        } catch (e) { alert('匯入失敗: ' + e.message); }
        finally { document.getElementById('btnRegister').innerText = "✨ 生成 2048-bit RSA 金鑰並上傳公鑰"; }
    }, 200);
});

// 功能 2：從專案 A 拿公鑰，加密並傳到專案 B
document.getElementById('btnSend').addEventListener('click', async () => {
    const myEmail = document.getElementById('myEmail').value.trim().toLowerCase();
    const targetEmail = document.getElementById('targetEmail').value.trim().toLowerCase();
    const msg = document.getElementById('msgContent').value;
    if (!myEmail || !targetEmail || !msg) return alert('請填寫完整！');
    try {
        const targetUserDoc = await getDocs(query(collection(dbKeyVault, "users"), where("email", "==", targetEmail)));
        if (targetUserDoc.empty) return alert('❌ 找不到該收件人的公鑰！');
        let targetPubKey = "";
        targetUserDoc.forEach(d => targetPubKey = d.data().public_key);
        const encryptedCiphertext = encryptRSA(msg, targetPubKey);
        await addDoc(collection(dbMessenger, "messages"), { sender_email: myEmail, receiver_email: targetEmail, encrypted_text: encryptedCiphertext, timestamp: Date.now() });
        alert('🚀 密文傳輸成功，已送入訊息專案！');
        document.getElementById('msgContent').value = "";
    } catch (e) { alert('傳輸失敗: ' + e.message); }
});

// 功能 3：從專案 B 下載密文並解密
document.getElementById('btnFetch').addEventListener('click', async () => {
    const myEmail = document.getElementById('myEmail').value.trim().toLowerCase();
    const privateKeyPem = document.getElementById('inputPrivateKey').value.trim();
    if (!myEmail || !privateKeyPem) return alert('請輸入 Email 與私鑰！');
    const chatHistory = document.getElementById('chatHistory');
    chatHistory.innerHTML = "⏳ 正在從訊息專案抓取密文...";
    try {
        const q = query(collection(dbMessenger, "messages"), where("receiver_email", "==", myEmail));
        const querySnapshot = await getDocs(q);
        chatHistory.innerHTML = "";
        if (querySnapshot.empty) { chatHistory.innerHTML = "目前沒有新訊息。"; return; }
        querySnapshot.forEach((doc) => {
            const data = doc.data();
            try {
                const decryptedText = decryptRSA(data.encrypted_text, privateKeyPem);
                chatHistory.innerHTML += `<div class="msg-item"><strong>📩 來自:</strong> ${data.sender_email}<br><strong>🔓 內文:</strong> ${decryptedText}</div>`;
            } catch (err) {
                chatHistory.innerHTML += `<div class="msg-item" style="border-left-color: #ef4444;"><strong>📩 來自:</strong> ${data.sender_email}<br><strong style="color:#ef4444;">❌ 解密失敗</strong></div>`;
            }
        });
    } catch (e) { alert('抓取失敗: ' + e.message); }
});