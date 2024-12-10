const servervless = 'vless.ari-andika.site';
const servertrojan = 'trojan.ari-andika.site';
const passuid = '7860871329:AAHzUpYg64zIZymSD2yEDMVZAnMgrXLvy3g';
const TELEGRAM_BOT_TOKEN = '7788002455:AAENxsebrlYrr1ctBF7T1JQG-ZKoaqSJnOIU';

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  if (request.method === 'POST') {
    const data = await request.json();
    const message = data.message || data.callback_query.message;
    const chatId = message.chat.id;
    const messageId = message.message_id;  // Menyimpan message_id untuk menghapus pesan nanti

    if (data.callback_query) {
      const callbackData = data.callback_query.data;
      if (callbackData.startsWith('confirm_trojan_')) {
        const ip = callbackData.split('_')[2];
        const port = callbackData.split('_')[3];
        const isp = callbackData.split('_')[4];
        const countryCode = callbackData.split('_')[5];
        const responseMessage = generateTrojanLink(ip, port, isp, countryCode);
        await deleteMessage(chatId, messageId);  // Menghapus pesan sebelumnya
        return sendMessage(chatId, responseMessage);
      } else if (callbackData.startsWith('confirm_vless_')) {
        const ip = callbackData.split('_')[2];
        const port = callbackData.split('_')[3];
        const isp = callbackData.split('_')[4];
        const countryCode = callbackData.split('_')[5];
        const responseMessage = generateVlessLink(ip, port, isp, countryCode);
        await deleteMessage(chatId, messageId);  // Menghapus pesan sebelumnya
        return sendMessage(chatId, responseMessage);
      } else if (callbackData.startsWith('cancel_')) {
        await deleteMessage(chatId, messageId);  // Menghapus pesan sebelumnya
        return sendMessage(chatId, 'Proses dibatalkan.');
      }
    } else {
      const ipAddress = message.text.trim();
      const [ip, port] = ipAddress.includes(':') ? ipAddress.split(':') : [ipAddress, '443'];

      if (!validateIP(ip) || !validatePort(port)) {
        return sendMessage(chatId, 'ððEasy Create VLESS and Trojan Serverlessðð\n\nKirim IP dan port dengan format berikut: <IP>:<Port>\n(Contoh: 192.168.1.1:8080)\nJika Anda tidak menyertakan port, bot akan menggunakan port default: 443.');
      }

      const checkUrl = `https://ipcheck.proxybox.us.kg/json?ip=${ip}&port=${port}`;
      try {
        const response = await fetch(checkUrl);
        const data = await response.json();

        if (data.status === "success" && data.proxyInfo.isProxy) {
          const proxyMessage = `
ð Proxy Host     : ${ip}
ðª Proxy Port      : ${port}
ð¡ ISP                    : ${data.isp}
ð Negara            : ${data.country} (${data.countryCode})
ð¡ï¸ Status Proxy   : Aktif
â±ï¸ Latency             : ${data.proxyInfo.latency}

Apakah Anda ingin melanjutkan dengan tautan Trojan atau VLESS?
`;
          const buttons = [
            { text: "Trojan", callback_data: `confirm_trojan_${ip}_${port}_${data.isp}_${data.countryCode}` },
            { text: "VLESS", callback_data: `confirm_vless_${ip}_${port}_${data.isp}_${data.countryCode}` },
            { text: "Tidak", callback_data: `cancel_${ip}_${port}` }
          ];
          return sendInlineKeyboard(chatId, proxyMessage, buttons);
        } else {
          return sendMessage(chatId, 'Proxy tidak aktif atau tidak valid. Silakan coba IP dan port lain.');
        }
      } catch (error) {
        return sendMessage(chatId, 'Error saat memeriksa status proxy.');
      }
    }
  } else {
    return new Response('Method not allowed', { status: 405 });
  }
}

async function sendMessage(chatId, text) {
  const telegramUrl = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
  const body = JSON.stringify({ chat_id: chatId, text: text });
  await fetch(telegramUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body });
  return new Response('OK', { status: 200 });
}

async function sendInlineKeyboard(chatId, text, buttons) {
  const telegramUrl = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
  const body = JSON.stringify({
    chat_id: chatId,
    text: text,
    reply_markup: { inline_keyboard: [buttons] }
  });
  await fetch(telegramUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body });
  return new Response('OK', { status: 200 });
}

async function deleteMessage(chatId, messageId) {
  const telegramUrl = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/deleteMessage`;
  const body = JSON.stringify({ chat_id: chatId, message_id: messageId });
  await fetch(telegramUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body });
}

function validateIP(ip) {
  const ipParts = ip.split('.');
  if (ipParts.length !== 4) return false;
  for (let part of ipParts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) return false;
  }
  return true;
}

function validatePort(port) {
  const portNum = parseInt(port, 10);
  return !isNaN(portNum) && portNum >= 1 && portNum <= 65535;
}

function generateTrojanLink(ip, port, isp, countryCode) {
  return `
==========TROJAN==========
ð TROJAN CONFIGURATION ð
==========================

ð TROJAN TLS ð
trojan://${passuid}@${servertrojan}:${port}?encryption=none&security=tls&sni=${servertrojan}&fp=randomized&type=ws&host=${servertrojan}&path=%2Ftrojan%3D${encodeURIComponent(ip)}%3D${port}=${isp} ${countryCode}

ð TROJAN NTLS ð
trojan://${passuid}@${servertrojan}:80?path=%2Ftrojan%3D${encodeURIComponent(ip)}%3D${port}&security=none&encryption=none&host=${servertrojan}&fp=randomized&type=ws&sni=${servertrojan}#${isp}%20${countryCode}

ð CLASH TROJAN ð
proxies:
- name: ${isp} ${countryCode}
  server: ${servertrojan}
  port: 443
  type: trojan
  password: ${passuid}
  skip-cert-verify: true
  network: ws
  sni: ${servertrojan}
  ws-opts:
    path: /tr=${encodeURIComponent(ip)}:${port}
    headers:
      Host: ${servertrojan}
  udp: true
  `;
}

function generateVlessLink(ip, port, isp, countryCode) {
  return `
==========VLESS==========
ð VLESS CONFIGURATION ð
=========================

ð VLESS TLS ð
vless://${passuid}@${servervless}:443?encryption=none&security=tls&sni=${servervless}&fp=randomized&type=ws&host=${servervless}&path=%2Fvl%3D${encodeURIComponent(ip)}%3A${port}#${isp}%20${countryCode}

ð VLESS NTLS ð
vless://${passuid}@${servervless}:443?path=%2Fvl%3D${encodeURIComponent(ip)}%3A${port}&security=none&encryption=none&host=${servervless}&fp=randomized&type=ws&sni=${servervless}#${isp}%20${countryCode}

ð CLASH VLESS ð
proxies:
- name: ${isp} ${countryCode}
  server: ${servervless}
  port: 443
  type: vless
  uuid: ${passuid}
  cipher: auto
  tls: true
  skip-cert-verify: true
  network: ws
  servername: ${servervless}
  ws-opts:
    path: /vl=${encodeURIComponent(ip)}:${port}
    headers:
      Host: ${servervless}
  udp: true
  `;
}
