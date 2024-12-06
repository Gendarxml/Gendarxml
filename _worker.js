import { connect } from "cloudflare:sockets";

let proxyIP;
let proxyPort;

var worker_default = {
  async fetch(request, env, ctx) {
    try {
      // Parse the list of proxies from the environment variable
      const listProxy = (env.LIST_IP_PORT || "")
        .split("\n")
        .filter(Boolean)
        .map(entry => {
          const [proxyIP, proxyPort, country, isp] = entry.split(",");
          return {
            proxyIP: proxyIP || "Unknown",
            proxyPort: proxyPort || "Unknown",
            country: country || "Unknown",
            isp: isp || "Unknown ISP"
          };
        });

      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);

      if (upgradeHeader === "websocket") {
        if (url.pathname.includes("/vl=")) {
          proxyIP = url.pathname.split("vl=")[1];
          return await vlessOverWSHandler(request);
        } else if (url.pathname.includes("/tr=")) {
          proxyIP = url.pathname.split("tr=")[1];
          return await trojanOverWSHandler(request);
        } else {
          proxyIP = "cdn.xn--b6gac.eu.org";
          return await vlessOverWSHandler(request);
        }
      }

      const allConfig = await getAllConfigVless(env, request.headers.get("Host"), listProxy);

      return new Response(allConfig, {
        status: 200,
        headers: { "Content-Type": "text/html;charset=utf-8" }
      });
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500
      });
    }
  }
}
async function getAllConfigVless(env, hostName, listProxy) {
  const listProxyElements = listProxy
    .map(({ proxyIP, proxyPort, country, isp }, index) => {
      const vlessTls = `vless://${generateUUIDv4()}@masukan.bug.ws:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2Fvl%3D${proxyIP}%3D${proxyPort}#(${country}) ${isp}`;
      const vlessNtls = `vless://${generateUUIDv4()}@masukan.bug.ws:80?path=%2Fvl%3D${proxyIP}%3D${proxyPort}&security=none&encryption=none&host=${hostName}&fp=randomized&type=ws&sni=${hostName}#(${country}) ${isp}`;
      const trojanTls = `trojan://${generatePASSWD()}@masukan.bug.ws:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2Ftr%3D${proxyIP}%3D${proxyPort}#(${country}) ${isp}`;
      const trojanNtls = `trojan://${generatePASSWD()}@masukan.bug.ws:80?path=%2Ftr%3D${proxyIP}%3D${proxyPort}&security=none&encryption=none&host=${hostName}&fp=randomized&type=ws&sni=${hostName}#(${country}) ${isp}`;

      return `
        <div class="content ${index === 0 ? "active" : ""}">
          <h2>VLESS & TROJAN CLOUDFLARE</h2><br>
          <h2>Free and Unlimited</h2><br>
          <hr class="config-divider"/>
          <center><h1>${country} (${isp})</h1></center>
          <center><h1>${proxyIP}:${proxyPort}</h1></center>
          <hr class="config-divider" />
          <h2>VLESS</h2>
          <pre>${vlessTls}</pre>
          <button onclick="copyToClipboard('${vlessTls}')">Copy Vless TLS</button>
          <pre>${vlessNtls}</pre>
          <button onclick="copyToClipboard('${vlessNtls}')">Copy Vless N-TLS</button>
          <hr class="config-divider" />
          <h2>TROJAN</h2>
          <pre>${trojanTls}</pre>
          <button onclick="copyToClipboard('${trojanTls}')">Copy Trojan TLS</button>
          <pre>${trojanNtls}</pre>
          <button onclick="copyToClipboard('${trojanNtls}')">Copy Trojan N-TLS</button>
          <hr class="config-divider" />
        </div>`;
    })
    .join("");

  return `
    <html>
      <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>Vless | AFRCloud | CloudFlare</title>
    <meta name="description" content="Akun Vless Gratis.">
    <meta name="keywords" content="AFRCloud, Vless Gratis, Free Vless, Vless CF, Trojan CF, Cloudflare">
    <meta name="author" content="AFRCloud">
    <meta name="robots" content="index, follow">

    <!-- Open Graph Meta Tags untuk SEO Media Sosial -->
    <meta property="og:title" content="Akun Vless Gratis - Akun Vless Cloudflare">
    <meta property="og:description" content="AFRCloud, Vless Gratis, Free Vless, Vless CF, Trojan CF, Cloudflare.">
    <meta property="og:image" content="https://img.freepik.com/free-photo/painting-mountain-lake-with-mountain-background_188544-9126.jpg"> <!-- Ganti dengan URL gambar yang sesuai -->
    <meta property="og:url" content="https://img.freepik.com/free-photo/painting-mountain-lake-with-mountain-background_188544-9126.jpg">
    <meta property="og:type" content="website">

    <!-- Twitter Card Meta Tags -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="Akun Vless Gratis - Akun Vless Cloudflare">
    <meta name="twitter:description" content="AFRCloud, Vless Gratis, Free Vless, Vless CF, Trojan CF, Cloudflare.">
    <meta name="twitter:image" content="https://img.freepik.com/free-photo/painting-mountain-lake-with-mountain-background_188544-9126.jpg"> <!-- Ganti dengan URL gambar yang sesuai -->
        <style>
  html, body {
    height: 100%;
    width: 100%;
    overflow: hidden;
    background-color: #1a1a1a;
    font-family: 'Roboto', Arial, sans-serif;
    margin: 0;
  }
  body {
    display: flex;
    background: url('https://raw.githubusercontent.com/bitzblack/ip/refs/heads/main/shubham-dhage-5LQ_h5cXB6U-unsplash.jpg') no-repeat center center fixed;
    background-size: cover;
    justify-content: center;
    align-items: center;
  }
  .popup {
    width: 100vw;
    height: 90vh;
    border-radius: 15px;
    background-color: rgba(0, 0, 0, 0.9);
    backdrop-filter: blur(8px);
    display: grid;
    grid-template-columns: 1.5fr 3fr;
    box-shadow: 0px 10px 20px rgba(255, 223, 0, 0.5); /* Efek kuning */
    overflow: hidden;
    animation: popupEffect 1s ease-in-out;
  }
  @keyframes popupEffect {
    0% { transform: scale(0.8); opacity: 0; }
    100% { transform: scale(1); opacity: 1; }
  }
  .tabs {
    background-color: #2a2a2a;
    padding: 10px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    overflow-y: auto;
    overflow-x: hidden;
    border-right: 2px solid #FFD700; /* Warna kuning */
    box-shadow: inset 0 0 10px rgba(255, 223, 0, 0.3); /* Glow kuning */
  }
  .author-link {
    position: absolute;
    bottom: 10px;
    right: 10px;
    font-weight: bold;
    font-style: italic;
    color: #FFD700; /* Warna kuning */
    font-size: 12px;
    text-decoration: none;
    z-index: 10;
  }
  .author-link:hover {
    color: #FFF700; /* Kuning lebih terang */
    text-shadow: 0px 0px 10px rgba(255, 223, 0, 0.7);
  }
  label {
    font-size: 12px;
    cursor: pointer;
    color: #FFD700; /* Warna kuning */
    padding: 10px;
    background-color: #333;
    border-radius: 8px;
    text-align: left;
    transition: background-color 0.3s ease, transform 0.3s ease;
    box-shadow: 0px 4px 6px rgba(255, 223, 0, 0.3); /* Glow kuning */
    white-space: normal;
    overflow-wrap: break-word;
  }
  label:hover {
    background-color: #FFD700; /* Kuning */
    color: #111;
    transform: translateY(-3px);
    box-shadow: 0px 8px 12px rgba(255, 223, 0, 0.7);
  }
  input[type="radio"] {
    display: none;
  }
  .tab-content {
    padding: 20px;
    overflow-y: auto;
    color: #FFFACD; /* Kuning pucat */
    font-size: 14px;
    background-color: #222;
    height: 100%;
    box-sizing: border-box;
    border-radius: 10px;
    box-shadow: inset 0 0 20px rgba(255, 223, 0, 0.2);
  }
  .content {
    display: none;
    padding-right: 15px;
  }
  .content.active {
    display: block;
    animation: fadeIn 0.5s ease;
  }
  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  h1 {
    font-size: 18px;
    color: #FFD700; /* Kuning */
    margin-bottom: 10px;
    text-shadow: 0px 0px 10px rgba(255, 223, 0, 0.5);
  }
  h2 {
    font-size: 22px;
    color: #FFD700; /* Kuning */
    text-align: center;
    text-shadow: 0px 0px 15px rgba(255, 223, 0, 0.7);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 8px;
  }
  pre {
    background-color: rgba(50, 50, 50, 0.8);
    padding: 10px;
    border-radius: 8px;
    font-size: 12px;
    white-space: pre-wrap;
    word-wrap: break-word;
    color: #FFD700; /* Kuning */
    border: 1px solid #FFD700;
    box-shadow: 0px 4px 8px rgba(255, 223, 0, 0.4);
  }
  .config-divider {
    border: none;
    height: 1px;
    background: linear-gradient(to right, transparent, #FFD700, transparent);
    margin: 40px 0;
  }
  .config-description {
    font-weight: bold;
    font-style: italic;
    color: #FFD700; /* Kuning */
    font-size: 14px;
    text-align: justify;
    margin: 0 10px; /* Tambahkan margin kiri-kanan agar tidak terlalu mepet */
  }
  button {
    padding: 8px 12px;
    border: none;
    border-radius: 5px;
    background-color: #FFD700;
    color: #111;
    cursor: pointer;
    font-weight: bold;
    display: block;
    text-align: left;
    box-shadow: 0px 4px 6px rgba(255, 223, 0, 0.5);
    transition: background-color 0.3s ease, transform 0.3s ease;
  }
  button:hover {
    background-color: #FFF700; /* Kuning lebih terang */
    transform: translateY(-3px);
    box-shadow: 0px 8px 12px rgba(255, 223, 0, 0.8);
  }
  #search {
    background: #333;
    color: #FFD700;
    border: 1px solid #FFD700;
    border-radius: 6px;
    padding: 5px;
    margin-bottom: 10px;
    width: 100%;
    box-shadow: 0px 0px 10px rgba(255, 223, 0, 0.3);
  }
  #search::placeholder {
    color: #FFD700;
  }
  .watermark {
    position: absolute;
    bottom: 10px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 0.8rem;
    color: rgba(255, 255, 255, 0.5);
    text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.5);
    font-weight: bold;
    text-align: center;
  }

  .watermark a {
    color: #e74c3c; /* Red */
    text-decoration: none;
    font-weight: bold;
}

  .watermark a:hover {
    color: #e74c3c; /* Red */
}

  @media (max-width: 768px) {
    .header h1 { font-size: 32px; }
    .config-section h3 { font-size: 24px; }
    .config-block h4 { font-size: 20px; }
  }
</style>
      </head>
      <body>
        <div class="popup">
          <div class="tabs">
            <input type="text" id="search" placeholder="Search by Country" oninput="filterTabs()">
            ${listProxy
              .map(
                ({ country, isp }, index) => `
                  <input type="radio" id="tab${index}" name="tab" ${index === 0 ? "checked" : ""}>
                  <label for="tab${index}" class="tab-label" data-country="${country.toLowerCase()}">${country} - ${isp}</label>
                `
              )
              .join("")}
          </div>
          <div class="tab-content">${listProxyElements}</div>
          <a href="https://t.me/Noir7R" class="watermark" target="_blank">@Noir7R</a>
        </div>
        <script>
          function filterTabs() {
            const query = document.getElementById('search').value.toLowerCase();
            const labels = document.querySelectorAll('.tab-label');
            labels.forEach(label => {
              const isVisible = label.dataset.country.includes(query);
              label.style.display = isVisible ? "block" : "none";
            });
          }

          function copyToClipboard(text) {
      navigator.clipboard.writeText(text)
        .then(() => {
          displayAlert("Successfully copied to clipboard!", '#FFD700');
        })
        .catch((err) => {
          displayAlert("Failed to copy to clipboard: " + err, '#cc2222');
        });
    }
    function displayAlert(message, backgroundColor) {
      const alertBox = document.createElement('div');
      alertBox.textContent = message;
      Object.assign(alertBox.style, {
          position: 'fixed',
          top: '20px',
          left: '50%',
          transform: 'translateX(-50%)',
          backgroundColor: backgroundColor,
          color: '#222',
          padding: '5px 10px',
          borderRadius: '5px',
          boxShadow: '0 4px 6px rgba(0,0,0,0.2)',
          opacity: '0',
          transition: 'opacity 0.5s ease-in-out',
          zIndex: '1000'
      });
      document.body.appendChild(alertBox);

      requestAnimationFrame(() => {
          alertBox.style.opacity = '1';
      });

      setTimeout(() => {
          alertBox.style.opacity = '0';
          setTimeout(() => {
              document.body.removeChild(alertBox);
          }, 500);
      }, 2000);
    }

          document.querySelectorAll('input[name="tab"]').forEach((tab, index) => {
            tab.addEventListener('change', () => {
              document.querySelectorAll('.content').forEach((content, idx) => {
                content.classList.toggle("active", idx === index);
              });
            });
          });
        </script>
      </body>
    </html>
  `;
}
function generateUUIDv4() {
  const randomValues = crypto.getRandomValues(new Uint8Array(16));
  randomValues[6] = (randomValues[6] & 0x0f) | 0x40;
  randomValues[8] = (randomValues[8] & 0x3f) | 0x80;
  return Array.from(randomValues)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
}

function generatePASSWD(length = 12) {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let password = "";
  const randomValues = crypto.getRandomValues(new Uint8Array(length));
  
  for (let i = 0; i < length; i++) {
    password += charset[randomValues[i] % charset.length];
  }
  
  return password;
}
async function vlessOverWSHandler(request) {
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	const log = (info, event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	let remoteSocketWapper = {
		value: null,
	};
	let udpStreamWrite = null;
	let isDns = false;

	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns && udpStreamWrite) {
				return udpStreamWrite(chunk);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				message,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				vlessVersion = new Uint8Array([0, 0]),
				isUDP,
			} = processVlessHeader(chunk);
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '
				} `;
			if (hasError) {
				throw new Error(message); 
				return;
			}
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error('UDP proxy only enable for DNS which is port 53');
					return;
				}
			}
			const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
				udpStreamWrite = write;
				udpStreamWrite(rawClientData);
				return;
			}
			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log,) {
	async function connectAndWrite(address, port) {
		const tcpSocket = connect({
			hostname: address,
			port: port,
		});
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}

	async function retry() {
		const tcpSocket = await connectAndWrite(proxyIP.split(/[:=]/)[0] || addressRemote, proxyIP.split(/[:=]/)[1] || portRemote);
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
	}

	const tcpSocket = await connectAndWrite(addressRemote, portRemote);

	remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});
			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			}
			);
			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			}
			);
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
		},
		cancel(reason) {
			if (readableStreamCancel) {
				return;
			}
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;

}
function processVlessHeader(
	vlessBuffer
) {
	if (vlessBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}
	const version = new Uint8Array(vlessBuffer.slice(0, 1));
	let isValidUser = true;
	let isUDP = false;
	if (!isValidUser) {
		return {
			hasError: true,
			message: 'invalid user',
		};
	}

	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];

	const command = new Uint8Array(
		vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];
	if (command === 1) {
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		vlessBuffer.slice(addressIndex, addressIndex + 1)
	);

	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			break;
		default:
			return {
				hasError: true,
				message: `invild  addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		vlessVersion: version,
		isUDP,
	};
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
	let remoteChunkCount = 0;
	let chunks = [];
	let vlessHeader = vlessResponseHeader;
	let hasIncomingData = false;
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				async write(chunk, controller) {
					hasIncomingData = true;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}
					if (vlessHeader) {
						webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
						vlessHeader = null;
					} else {
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
				},
				abort(reason) {
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch((error) => {
			console.error(
				`remoteSocketToWS has exception `,
				error.stack || error
			);
			safeCloseWebSocket(webSocket);
		});
	if (hasIncomingData === false && retry) {
		log(`retry`)
		retry();
	}
}

function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { error };
	}
}


const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {

	let isVlessHeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {

		},
		transform(chunk, controller) {
			for (let index = 0; index < chunk.byteLength;) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
				const udpData = new Uint8Array(
					chunk.slice(index + 2, index + 2 + udpPakcetLength)
				);
				index = index + 2 + udpPakcetLength;
				controller.enqueue(udpData);
			}
		},
		flush(controller) {
		}
	});
	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch('https://1.1.1.1/dns-query',
				{
					method: 'POST',
					headers: {
						'content-type': 'application/dns-message',
					},
					body: chunk,
				})
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				log(`doh success and dns message length is ${udpSize}`);
				if (isVlessHeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isVlessHeaderSent = true;
				}
			}
		}
	})).catch((error) => {
		log('dns udp has error' + error)
	});

	const writer = transformStream.writable.getWriter();

	return {
		write(chunk) {
			writer.write(chunk);
		}
	};
}


async function trojanOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  let address = "";
  let portWithRandomLog = "";
  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream2(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = {
    value: null,
  };
  let udpStreamWrite = null;
  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }
          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = "",
            rawClientData,
          } = await parseTrojanHeader(chunk);
          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} tcp`;
          if (hasError) {
            throw new Error(message);
            return;
          }
          handleTCPOutBound2(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log);
        },
        close() {
          log(`readableWebSocketStream is closed`);
        },
        abort(reason) {
          log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });
  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function parseTrojanHeader(buffer) {
  if (buffer.byteLength < 56) {
    return {
      hasError: true,
      message: "invalid data",
    };
  }
  let crLfIndex = 56;
  if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
    return {
      hasError: true,
      message: "invalid header format (missing CR LF)",
    };
  }

  const socks5DataBuffer = buffer.slice(crLfIndex + 2);
  if (socks5DataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid SOCKS5 request data",
    };
  }

  const view = new DataView(socks5DataBuffer);
  const cmd = view.getUint8(0);
  if (cmd !== 1) {
    return {
      hasError: true,
      message: "unsupported command, only TCP (CONNECT) is allowed",
    };
  }

  const atype = view.getUint8(1);
  let addressLength = 0;
  let addressIndex = 2;
  let address = "";
  switch (atype) {
    case 1:
      addressLength = 4;
      address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
      addressIndex += 1;
      address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      address = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${atype}`,
      };
  }

  if (!address) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${atype}`,
    };
  }

  const portIndex = addressIndex + addressLength;
  const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: address,
    portRemote,
    rawClientData: socks5DataBuffer.slice(portIndex + 4),
  };
}

async function handleTCPOutBound2(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket2 = connect({
      hostname: address,
      port,
    });
    remoteSocket.value = tcpSocket2;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }
  async function retry() {
    const tcpSocket2 = await connectAndWrite(proxyIP.split(/[:=]/)[0] || addressRemote, proxyIP.split(/[:=]/)[1] || portRemote);
    tcpSocket2.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket2(webSocket);
      });
    remoteSocketToWS2(tcpSocket2, webSocket, null, log);
  }
  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS2(tcpSocket, webSocket, retry, log);
}

function makeReadableWebSocketStream2(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket2(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer2(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`readableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket2(webSocketServer);
    },
  });
  return stream;
}

async function remoteSocketToWS2(remoteSocket, webSocket, retry, log) {
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket connection is not open");
          }
          webSocket.send(chunk);
        },
        close() {
          log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
        },
        abort(reason) {
          console.error("remoteSocket.readable abort", reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS2 error:`, error.stack || error);
      safeCloseWebSocket2(webSocket);
    });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

function base64ToArrayBuffer2(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

let WS_READY_STATE_OPEN2 = 1;
let WS_READY_STATE_CLOSING2 = 2;

function safeCloseWebSocket2(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN2 || socket.readyState === WS_READY_STATE_CLOSING2) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket2 error", error);
  }
}

export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
