const servervless = 'gendarbot.ari-andikha.web.id';
const servertrojan = 'gendarbot.ari-andikha.web.id';
const passuid = '6ac83a31-453a-45a3-b01d-1bd20ee9101f';
const TELEGRAM_BOT_TOKEN = '7921302665:AAFynbwLQWJOTRCTnnsINj-mUueAnq6ENVc';
const TELEGRAM_USER_ID = 'ariyelDlacasa'; // Nama Telegram pengguna

// Menyimpan ID chat pengguna yang sudah menerima pesan kesalahan
const usersWithError = new Set();

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  try {
    if (request.method === 'POST') {
      const data = await request.json();
      const message = data.message || data.callback_query?.message;
      const chatId = message.chat.id;
      const text = message.text?.trim();

      console.log(`Received message: ${text}`); // Logging the incoming message

      // Kata sambutan untuk perintah /start
      if (text === "/start") {
        const welcomeMessage = `
🎉 Selamat datang di Bot Akun VLESS dan Trojan! 🎉

👤 Bot ini dioperasikan oleh @ariyelDlacasa.

Gunakan format berikut untuk membuat akun:
🔹 Kirim *Proxy:Port* (contoh: 192.168.1.1:443)
🔹 Bot akan memproses dan mengirimkan tautan Trojan dan VLESS.

Contoh:
192.168.1.1:443

Klik di bawah untuk mencari proxy aktif:
[Daftar Proxy Aktif](https://github.com/Gendarxml/BAHAN/blob/main/List%20Paket)

Silakan kirim proxy dan port sekarang!
`;

        // Kirim sambutan tanpa foto, tetap mempertahankan link GitHub
        await sendMessage(chatId, welcomeMessage);
        return new Response("OK");
      }

      // Jika format input adalah Proxy:Port
      if (text?.includes(":")) {
        const [proxy, port] = text.split(":");
        if (!validateIP(proxy) || !validatePort(port)) {
          // Hanya kirim pesan kesalahan jika pengguna belum menerima pesan kesalahan
          if (!usersWithError.has(chatId)) {
            await sendMessage(chatId, `❌ Format salah! Kirim dengan format Proxy:Port\nContoh: 192.168.1.1:443`);
            usersWithError.add(chatId);  // Tandai pengguna yang sudah menerima pesan kesalahan
          }
          return new Response("OK");
        }

        // Mendapatkan informasi proxy
        try {
          const proxyInfo = await getProxyInfo(proxy);

          // Jika proxy tidak aktif, beri tahu pengguna
          if (proxyInfo.status === 'fail') {
            await sendMessage(chatId, `❌ Proxy tidak aktif! Cek kembali alamat proxy dan coba lagi.`);
            return new Response("OK");
          }

          const vlessLink = generateVlessLink(proxy, port);
          const trojanLink = generateTrojanLink(proxy, port);

          const responseMessage = `
✅ Berikut akun Anda:

🔹 **Alamat Proxy**: ${proxyInfo.address}
🔹 **Nama Proxy**: ${proxyInfo.isp}
🔹 **Negara**: ${proxyInfo.country}

🔹 **Trojan Link**:
\`\`\`
${trojanLink}
\`\`\`
------------------------------------

🔹 **VLESS Link**:
\`\`\`
${vlessLink}
\`\`\`
------------------------------------

Selamat menggunakan akun Anda!
`;

          await sendMessage(chatId, responseMessage);
        } catch (error) {
          console.error('Error getting proxy information:', error);
          await sendMessage(chatId, `❌ Gagal mendapatkan informasi proxy. Coba lagi nanti.`);
        }

        return new Response("OK");
      }

      // Jika format tidak dikenali
      await sendMessage(chatId, `❌ Format tidak dikenali! Kirim dengan format Proxy:Port\nContoh: 192.168.1.1:443`);
      return new Response("OK");
    } else {
      return new Response("Method Not Allowed", { status: 405 });
    }
  } catch (error) {
    console.error('Error processing request:', error); // Improved error logging
    return new Response("Internal Server Error", { status: 500 });
  }
}

// Fungsi untuk mengirim pesan ke Telegram
async function sendMessage(chatId, text, photoUrl = null) {
  const telegramUrl = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
  const body = JSON.stringify({ chat_id: chatId, text: text, parse_mode: "Markdown" });
  
  try {
    const response = await fetch(telegramUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body });
    if (!response.ok) {
      throw new Error(`Telegram API responded with status: ${response.status}`);
    }
  } catch (error) {
    console.error('Error sending message to Telegram:', error); // Log error if message sending fails
  }
}

// Fungsi untuk mendapatkan informasi proxy
async function getProxyInfo(proxy) {
  // Menggunakan ip-api untuk mendapatkan informasi lokasi proxy dan ISP
  const apiUrl = `http://ip-api.com/json/${proxy}?fields=country,regionName,city,isp,query,status`;
  const response = await fetch(apiUrl);
  const data = await response.json();

  // Periksa apakah response valid dan data yang diperlukan ada
  if (data.status === 'fail') {
    return { status: 'fail' };  // Menandakan proxy tidak aktif
  }

  return {
    address: data.query,  // Alamat Proxy (IP)
    country: data.country, // Nama Negara
    region: data.regionName, // Wilayah
    city: data.city, // Kota
    isp: data.isp, // Nama ISP / Provider Proxy
    status: 'active', // Proxy aktif
  };
}

// Validasi Proxy (IP Address)
function validateIP(ip) {
  const ipParts = ip.split(".");
  return ipParts.length === 4 && ipParts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
}

// Validasi Port
function validatePort(port) {
  const num = parseInt(port, 10);
  return num >= 1 && num <= 65535;
}

// Generate VLESS Link dengan nama Telegram
function generateVlessLink(proxy, port) {
  return `vless://${passuid}@${servervless}:443?encryption=none&security=tls&sni=${servervless}&fp=randomized&type=ws&host=${servervless}&path=%2F${proxy}%3A${port}#${TELEGRAM_USER_ID}`;
}

// Generate Trojan Link dengan nama Telegram
function generateTrojanLink(proxy, port) {
  return `trojan://${passuid}@${servertrojan}:443?encryption=none&security=tls&sni=${servertrojan}&fp=randomized&type=ws&host=${servertrojan}&path=%2F${proxy}%3A${port}#${TELEGRAM_USER_ID}`;
}
