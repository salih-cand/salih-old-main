import WebSocket from 'ws';
import tls from 'tls';

const USER_TOKEN = 'TOKEN';
const TARGET_GUILD_ID = 'URL CEKİCEĞİN SW';
const USER_PASSWORD = 'TOKENİN ŞİFRESİ';

let mfaAuthToken = null;
let latestSequence = null;
let heartbeatTimer = null;
let tlsSocket = null;
const vanityMap = new Map();

function createTlsSocket() {
  return tls.connect({
    host: 'canary.discord.com',
    port: 443,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2'
  });
}

function sendHttpRequest(method, path, body = null, extraHeaders = {}, closeConnection = false) {
  return new Promise((resolve) => {
    const payload = body ? JSON.stringify(body) : '';
    if (!tlsSocket || tlsSocket.destroyed || closeConnection) {
      tlsSocket = createTlsSocket();
      tlsSocket.setNoDelay(true);
    }
    const socket = tlsSocket;

    const headers = [
      `${method} ${path} HTTP/1.1`,
      'Host: canary.discord.com',
      `Connection: ${closeConnection ? 'close' : 'keep-alive'}`,
      'Content-Type: application/json',
      `Content-Length: ${Buffer.byteLength(payload)}`,
      'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0)',
      `Authorization: ${USER_TOKEN}`,
      'X-Super-Properties: eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRmlyZWZveCIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJ0ci1UUiIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEzMy4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEzMy4wIiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTMzLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6Imh0dHBzOi8vd3d3Lmdvb2dsZS5jb20vIiwicmVmZXJyaW5nX2RvbWFpbiI6Ind3dy5nb29nbGUuY29tIiwic2VhcmNoX2VuZ2luZSI6Imdvb2dsZSIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNTYxNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGwsImhhc19jbGllbnRfbW9kcyI6ZmFsc2V9'
    ];

    if (extraHeaders['X-Discord-MFA-Authorization']) {
      headers.push(`X-Discord-MFA-Authorization: ${extraHeaders['X-Discord-MFA-Authorization']}`);
    }

    headers.push('', payload);

    let responseData = '';
    socket.write(headers.join('\r\n'));

    socket.once('error', () => resolve('{}'));

    socket.on('data', (chunk) => {
      responseData += chunk.toString();
    });

    socket.once('end', () => {
      try {
        const separatorIndex = responseData.indexOf('\r\n\r\n');
        if (separatorIndex === -1) return resolve('{}');
        let bodyData = responseData.slice(separatorIndex + 4);

        if (responseData.toLowerCase().includes('transfer-encoding: chunked')) {
          let decoded = '';
          let pos = 0;
          while (pos < bodyData.length) {
            const sizeEnd = bodyData.indexOf('\r\n', pos);
            if (sizeEnd === -1) break;
            const size = parseInt(bodyData.substring(pos, sizeEnd), 16);
            if (size === 0) break;
            decoded += bodyData.substr(sizeEnd + 2, size);
            pos = sizeEnd + 2 + size + 2;
          }
          resolve(decoded || '{}');
        } else {
          resolve(bodyData || '{}');
        }
      } catch {
        resolve('{}');
      } finally {
        if (closeConnection) socket.destroy();
      }
    });
  });
}

async function authenticateMfa() {
  try {
    const patchResp = await sendHttpRequest('PATCH', `/api/v7/guilds/${TARGET_GUILD_ID}/vanity-url`, null, {}, true);
    const patchData = JSON.parse(patchResp);

    if (patchData.code === 60003) {
      const finishResp = await sendHttpRequest('POST', '/api/v9/mfa/finish', {
        ticket: patchData.mfa.ticket,
        mfa_type: 'password',
        data: USER_PASSWORD
      }, {}, true);

      const finishData = JSON.parse(finishResp);
      if (finishData.token) {
        console.log('salih mfayi gecti :D');
        return finishData.token;
      }
    }
  } catch {}
  return null;
}

function establishGatewayConnection() {
  const ws = new WebSocket('wss://gateway-us-east1-b.discord.gg');

  ws.on('open', () => {
    ws.send(JSON.stringify({
      op: 2,
      d: {
        token: USER_TOKEN,
        intents: 513,
        properties: { $os: 'linux', $browser: '', $device: '' }
      }
    }));
  });

  ws.on('message', async (msg) => {
    const packet = JSON.parse(msg);
    if (packet.s) latestSequence = packet.s;

    if (packet.op === 10) {
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(() => {
        ws.send(JSON.stringify({ op: 1, d: latestSequence }));
      }, packet.d.heartbeat_interval);
    } else if (packet.op === 0) {
      if (packet.t === 'GUILD_UPDATE') {
        const oldCode = vanityMap.get(packet.d.guild_id);
        if (oldCode && oldCode !== packet.d.vanity_url_code) {
          for (let i = 0; i < 3; i++) {
            sendHttpRequest('PATCH', `/api/v7/guilds/${TARGET_GUILD_ID}/vanity-url`, {
              code: oldCode
            }, { 'X-Discord-MFA-Authorization': mfaAuthToken });
          }
        }
      } else if (packet.t === 'READY') {
        packet.d.guilds.forEach(g => {
          if (g.vanity_url_code) {
            vanityMap.set(g.id, g.vanity_url_code);
          }
        });
        console.log('discorda baglanildi salih sagolsun:', [...vanityMap.entries()]);
      }
    }
  });

  ws.on('close', () => {
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    setTimeout(establishGatewayConnection, 5000);
  });

  ws.on('error', () => ws.close());
}

async function main() {
  mfaAuthToken = await authenticateMfa();
  setInterval(async () => {
    const refreshedToken = await authenticateMfa();
    if (refreshedToken) mfaAuthToken = refreshedToken;
  }, 4 * 60 * 1000);

  establishGatewayConnection();
}

main();
