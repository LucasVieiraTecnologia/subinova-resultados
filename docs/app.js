(function () {
  'use strict';

  const LOCAL_STORAGE_KEYS = 'subinova_chaves_acesso';
  const LOCAL_STORAGE_CLOUD = 'subinova_cloud_config';

  // Elementos do DOM
  const pbiLayer = document.getElementById('pbi-layer');
  const pbiLoading = document.getElementById('pbi-loading');
  const pbiIframe = document.getElementById('pbi-iframe');
  const bgVideo = document.getElementById('bg-video');
  const btnSkipVideo = document.getElementById('btn-skip-video');
  const authModal = document.getElementById('auth-modal');
  const authBanner = document.getElementById('auth-banner');
  const authBannerText = document.getElementById('auth-banner-text');
  const authForm = document.getElementById('auth-form');
  const passwordInput = document.getElementById('password-input');
  const btnToggleEye = document.getElementById('btn-toggle-eye');
  const authError = document.getElementById('auth-error');
  const authErrorText = document.getElementById('auth-error-text');
  const authCard = document.querySelector('.auth-card');
  const securityAlertModal = document.getElementById('security-alert-modal');
  const btnSecurityReload = document.getElementById('btn-security-reload');

  let modalOpened = false;
  let isDevToolsTriggered = false;

  /* ==========================================================================
     ALGORITMO SHA-256
     ========================================================================== */
  function sha256Sync(ascii) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var lengthProperty = 'length';
    var i, j;
    var result = '';
    var words = [];
    var asciiBitLength = ascii[lengthProperty] * 8;

    var hash = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    var k = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    var composite = [];
    for (i = 0; i < ascii[lengthProperty]; i++) {
      var code = ascii.charCodeAt(i);
      if (code < 128) composite.push(code);
      else if (code < 2048) {
        composite.push((code >> 6) | 192, (code & 63) | 128);
      } else {
        composite.push((code >> 12) | 224, ((code >> 6) & 63) | 128, (code & 63) | 128);
      }
    }
    asciiBitLength = composite.length * 8;
    composite.push(0x80);
    while ((composite.length % 64) !== 56) composite.push(0);
    for (i = 0; i < composite.length; i += 4) {
      words.push((composite[i] << 24) | (composite[i + 1] << 16) | (composite[i + 2] << 8) | composite[i + 3]);
    }
    words.push(Math.floor(asciiBitLength / maxWord));
    words.push(asciiBitLength >>> 0);

    var w = new Array(64);
    for (i = 0; i < words.length; i += 16) {
      var a = hash[0], b = hash[1], c = hash[2], d = hash[3];
      var e = hash[4], f = hash[5], g = hash[6], h = hash[7];

      for (j = 0; j < 64; j++) {
        if (j < 16) {
          w[j] = words[i + j];
        } else {
          var gamma0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
          var gamma1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
          w[j] = (w[j - 16] + gamma0 + w[j - 7] + gamma1) >>> 0;
        }

        var ch = (e & f) ^ (~e & g);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var sigma0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        var sigma1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        var t1 = (h + sigma1 + ch + k[j] + w[j]) >>> 0;
        var t2 = (sigma0 + maj) >>> 0;

        h = g; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }

      hash[0] = (hash[0] + a) >>> 0;
      hash[1] = (hash[1] + b) >>> 0;
      hash[2] = (hash[2] + c) >>> 0;
      hash[3] = (hash[3] + d) >>> 0;
      hash[4] = (hash[4] + e) >>> 0;
      hash[5] = (hash[5] + f) >>> 0;
      hash[6] = (hash[6] + g) >>> 0;
      hash[7] = (hash[7] + h) >>> 0;
    }

    for (i = 0; i < 8; i++) {
      for (j = 3; j >= 0; j--) {
        var byteVal = (hash[i] >> (j * 8)) & 255;
        result += (byteVal < 16 ? '0' : '') + byteVal.toString(16);
      }
    }
    return result;
  }

  async function computeSHA256(message) {
    if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
      try {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (e) {
        return sha256Sync(message);
      }
    }
    return sha256Sync(message);
  }

  /* ==========================================================================
     TELEMETRIA & AUDITORIA DE ACESSOS (IP, GEOLOCALIZAÇÃO E DISPOSITIVO)
     ========================================================================== */
  function getClientDeviceInfo() {
    const ua = navigator.userAgent || '';
    let os = 'Desktop';
    if (/windows/i.test(ua)) os = 'Windows';
    else if (/iphone|ipad|ipod/i.test(ua)) os = 'iOS';
    else if (/android/i.test(ua)) os = 'Android';
    else if (/macintosh|mac os x/i.test(ua)) os = 'macOS';
    else if (/linux/i.test(ua)) os = 'Linux';

    let browser = 'Navegador';
    if (/edg/i.test(ua)) browser = 'Edge';
    else if (/chrome|crios/i.test(ua)) browser = 'Chrome';
    else if (/firefox|fxios/i.test(ua)) browser = 'Firefox';
    else if (/safari/i.test(ua)) browser = 'Safari';
    else if (/opr\//i.test(ua)) browser = 'Opera';

    return { os, browser };
  }

  let cachedIpInfo = null;
  async function fetchIpLocation() {
    if (cachedIpInfo) return cachedIpInfo;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2200);
      const res = await fetch('https://ipapi.co/json/', { signal: controller.signal });
      clearTimeout(timeoutId);
      if (res.ok) {
        const d = await res.json();
        cachedIpInfo = {
          ip: d.ip || 'Desconhecido',
          cidade: d.city || 'N/A',
          regiao: d.region || 'N/A',
          pais: d.country_name || 'Brasil',
          provedor: d.org || 'N/A'
        };
        return cachedIpInfo;
      }
    } catch (e) {
      try {
        const resIp = await fetch('https://api.ipify.org?format=json');
        if (resIp.ok) {
          const d = await resIp.json();
          cachedIpInfo = { ip: d.ip, cidade: 'N/A', regiao: 'N/A', pais: 'Brasil', provedor: 'N/A' };
          return cachedIpInfo;
        }
      } catch (err) {}
    }
    return { ip: 'Desconhecido', cidade: 'N/A', regiao: 'N/A', pais: 'Brasil', provedor: 'N/A' };
  }

  /* ==========================================================================
     PROTEÇÃO CONTRA FORÇA BRUTA (BLOQUEIO TEMPORÁRIO APÓS 5 FALHAS)
     ========================================================================== */
  const Security = {
    KEY: 'subinova_sec_lockout',
    MAX_ATTEMPTS: 5,
    LOCK_DURATION_MS: 3 * 60 * 1000, // 3 minutos

    getState() {
      try {
        const raw = JSON.parse(localStorage.getItem(this.KEY));
        if (!raw) return { attempts: 0, lockedUntil: 0, isLocked: false };
        if (raw.lockedUntil && Date.now() > raw.lockedUntil) {
          this.reset();
          return { attempts: 0, lockedUntil: 0, isLocked: false };
        }
        return {
          attempts: raw.attempts || 0,
          lockedUntil: raw.lockedUntil || 0,
          isLocked: Boolean(raw.lockedUntil && Date.now() < raw.lockedUntil)
        };
      } catch (e) {
        return { attempts: 0, lockedUntil: 0, isLocked: false };
      }
    },

    recordFailure() {
      const s = this.getState();
      s.attempts = (s.attempts || 0) + 1;
      if (s.attempts >= this.MAX_ATTEMPTS) {
        s.lockedUntil = Date.now() + this.LOCK_DURATION_MS;
        s.isLocked = true;
      }
      localStorage.setItem(this.KEY, JSON.stringify(s));
      return s;
    },

    reset() {
      localStorage.removeItem(this.KEY);
    }
  };

  /* ==========================================================================
     CAMADA DE VALIDAÇÃO BLINDADA (SUPABASE RPC SERVER-SIDE)
     ========================================================================== */
  const KeyStore = {
    getCloudConfig() {
      if (window.SUBINOVA_CLOUD_CONFIG && window.SUBINOVA_CLOUD_CONFIG.url && window.SUBINOVA_CLOUD_CONFIG.key) {
        return window.SUBINOVA_CLOUD_CONFIG;
      }
      try {
        const local = JSON.parse(localStorage.getItem(LOCAL_STORAGE_CLOUD));
        if (local && local.url && local.key) return local;
      } catch (e) {}
      return null;
    },

    async fetchPortalStatus() {
      const cfg = this.getCloudConfig();
      if (cfg && cfg.url && cfg.key) {
        try {
          const res = await fetch(`${cfg.url}/rest/v1/rpc/obter_status_portal`, {
            method: 'POST',
            headers: {
              'apikey': cfg.key,
              'Authorization': `Bearer ${cfg.key}`,
              'Content-Type': 'application/json'
            },
            body: '{}'
          });
          if (res.ok) {
            const data = await res.json();
            return {
              modo_manutencao: Boolean(data.modo_manutencao),
              mensagem_manutencao: data.mensagem_manutencao || '',
              banner_ativo: Boolean(data.banner_ativo),
              banner_mensagem: data.banner_mensagem || '',
              whatsapp_ativo: Boolean(data.whatsapp_ativo),
              whatsapp_phone: data.whatsapp_phone || '',
              whatsapp_apikey: data.whatsapp_apikey || '',
              whatsapp_notificar_sucesso: data.whatsapp_notificar_sucesso !== false,
              whatsapp_notificar_falha: Boolean(data.whatsapp_notificar_falha),
              whatsapp_notificar_devtools: Boolean(data.whatsapp_notificar_devtools)
            };
          }
        } catch (e) {}
      }
      return {
        modo_manutencao: localStorage.getItem('subinova_modo_manutencao') === 'true',
        mensagem_manutencao: 'Painel em manutenção temporária.',
        banner_ativo: localStorage.getItem('subinova_banner_ativo') === 'true',
        banner_mensagem: localStorage.getItem('subinova_banner_msg') || '',
        whatsapp_ativo: localStorage.getItem('subinova_wpp_ativo') === 'true',
        whatsapp_phone: localStorage.getItem('subinova_wpp_phone') || '',
        whatsapp_apikey: localStorage.getItem('subinova_wpp_apikey') || '',
        whatsapp_notificar_sucesso: localStorage.getItem('subinova_wpp_suc') !== 'false',
        whatsapp_notificar_falha: localStorage.getItem('subinova_wpp_falha') === 'true',
        whatsapp_notificar_devtools: localStorage.getItem('subinova_wpp_dev') === 'true'
      };
    },

    async validateServerSide(password, registrarFalha) {
      const cfg = this.getCloudConfig();
      const clean = password.trim();
      const hash = await computeSHA256(clean);

      if (cfg && cfg.url && cfg.key) {
        const device = getClientDeviceInfo();
        const ipInfo = registrarFalha ? await fetchIpLocation() : (cachedIpInfo || {
          ip: 'Desconhecido',
          cidade: 'N/A',
          regiao: 'N/A',
          pais: 'Brasil',
          provedor: 'N/A'
        });

        const payload = {
          p_chave: clean,
          p_hash: hash,
          p_ip: ipInfo.ip || 'N/A',
          p_cidade: ipInfo.cidade || 'N/A',
          p_regiao: ipInfo.regiao || 'N/A',
          p_pais: ipInfo.pais || 'Brasil',
          p_provedor: ipInfo.provedor || 'N/A',
          p_dispositivo: device.os,
          p_navegador: device.browser,
          p_registrar_falha: Boolean(registrarFalha)
        };

        const res = await fetch(`${cfg.url}/rest/v1/rpc/validar_chave_acesso`, {
          method: 'POST',
          headers: {
            'apikey': cfg.key,
            'Authorization': `Bearer ${cfg.key}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        });

        if (res.ok) {
          return await res.json();
        }
        return { ok: false, error: 'Erro de comunicação com o servidor de autenticação.' };
      }

      // Modo estritamente local (quando não há nuvem configurada)
      const raw = localStorage.getItem(LOCAL_STORAGE_KEYS);
      const keys = raw ? JSON.parse(raw) : [];
      const match = keys.find(k => k.chave_hash === hash || k.chave === clean);
      if (!match) return { ok: false, error: 'Senha incorreta.' };
      if (!match.ativa) return { ok: false, error: 'Esta chave de acesso foi desativada.' };
      if (match.expira_em && Date.now() > new Date(match.expira_em).getTime()) {
        return { ok: false, error: 'Esta chave de acesso expirou.' };
      }
      if (match.limite_usos && Number(match.limite_usos) > 0 && (match.total_usos || 0) >= Number(match.limite_usos)) {
        return { ok: false, error: 'Limite de utilizações atingido.' };
      }
      match.total_usos = (match.total_usos || 0) + 1;
      match.ultimo_acesso = new Date().toISOString();
      localStorage.setItem(LOCAL_STORAGE_KEYS, JSON.stringify(keys));
      return { 
        ok: true, 
        pbi_url: '',
        rotulo: match.rotulo || 'SUBINOVA',
        ip: '127.0.0.1 (Local)',
        sessao_ilimitada: Boolean(match.sessao_ilimitada)
      };
    }
  };

  /* ==========================================================================
     ABERTURA DO MODAL DE AUTENTICAÇÃO
     ========================================================================== */
  async function showAuthModal() {
    if (modalOpened) return;
    modalOpened = true;

    if (btnSkipVideo) {
      btnSkipVideo.classList.add('hidden');
    }

    if (bgVideo) {
      bgVideo.classList.add('dimmed');
      try { bgVideo.pause(); } catch (e) {}
    }

    try {
      const status = await KeyStore.fetchPortalStatus();
      if (status.banner_ativo && status.banner_mensagem && authBanner && authBannerText) {
        authBannerText.textContent = status.banner_mensagem;
        authBanner.classList.remove('hidden');
      }
    } catch (e) {}

    authModal.classList.remove('hidden');
    passwordInput.value = '';
    authError.classList.remove('visible');

    const lockState = Security.getState();
    if (lockState.isLocked) {
      startLockoutCountdown(lockState.lockedUntil);
    } else {
      passwordInput.focus();
    }
  }

  function startLockoutCountdown(until) {
    passwordInput.disabled = true;
    authError.classList.add('visible');

    function update() {
      const rem = Math.ceil((until - Date.now()) / 1000);
      if (rem <= 0) {
        Security.reset();
        passwordInput.disabled = false;
        authError.classList.remove('visible');
        passwordInput.focus();
        return;
      }
      const mins = Math.floor(rem / 60).toString().padStart(2, '0');
      const secs = (rem % 60).toString().padStart(2, '0');
      if (authErrorText) {
        authErrorText.textContent = `Muitas tentativas incorretas. Aguarde ${mins}:${secs} antes de tentar novamente.`;
      }
      setTimeout(update, 1000);
    }
    update();
  }

  /* ==========================================================================
     INTEGRAÇÃO COM WHATSAPP (CALLMEBOT API)
     ========================================================================== */
  let cachedPortalStatus = null;
  let lastAttemptedKey = '';

  async function sendWhatsAppAlert(text) {
    if (!cachedPortalStatus) {
      try {
        cachedPortalStatus = await KeyStore.fetchPortalStatus();
      } catch (e) {}
    }
    if (!cachedPortalStatus || !cachedPortalStatus.whatsapp_ativo) return;
    const phone = cachedPortalStatus.whatsapp_phone;
    const apikey = cachedPortalStatus.whatsapp_apikey;
    if (!phone || !apikey) return;

    try {
      const url = `https://api.callmebot.com/whatsapp.php?phone=${encodeURIComponent(phone)}&text=${encodeURIComponent(text)}&apikey=${encodeURIComponent(apikey)}`;
      fetch(url, { mode: 'no-cors' }).catch(() => {});
    } catch (e) {}
  }

  /* ==========================================================================
     VALIDAÇÃO DA SENHA & LIBERAÇÃO DO POWER BI
     ========================================================================== */
  async function validateAccessKey(password) {
    if (!password) return { ok: false, error: 'Digite uma senha.' };
    lastAttemptedKey = password.trim();

    const sec = Security.getState();
    if (sec.isLocked) {
      return { ok: false, error: 'Acesso temporariamente bloqueado por excesso de tentativas.' };
    }

    const result = await KeyStore.validateServerSide(password, true);

    if (result && result.ok) {
      Security.reset();
      return { 
        ok: true, 
        pbi_url: result.pbi_url,
        rotulo: result.rotulo || 'SUBINOVA',
        ip: result.ip || (cachedIpInfo ? cachedIpInfo.ip : '0.0.0.0'),
        sessao_ilimitada: Boolean(result.sessao_ilimitada)
      };
    }

    const afterFail = Security.recordFailure();
    if (afterFail.isLocked || (result && result.locked)) {
      const lockUntil = afterFail.lockedUntil || (Date.now() + Security.LOCK_DURATION_MS);
      startLockoutCountdown(lockUntil);
      if (cachedPortalStatus && cachedPortalStatus.whatsapp_notificar_falha) {
        const ipDisp = cachedIpInfo ? cachedIpInfo.ip : '0.0.0.0';
        const dev = getClientDeviceInfo();
        sendWhatsAppAlert(
          `⚠️ *SUBINOVA · TENTATIVA BLOQUEADA*\n` +
          `━━━━━━━━━━━━━━━━━━━━\n` +
          `🔑 *Chave Tentada:* ${password}\n` +
          `🚫 *Motivo:* Limite de 5 tentativas atingido (Bloqueio 3min)\n` +
          `🌐 *IP:* ${ipDisp}\n` +
          `💻 *Dispositivo:* ${dev.os} · ${dev.browser}`
        );
      }
      return { ok: false, error: (result && result.error) || 'Limite de 5 tentativas atingido. Bloqueado por 3 minutos.' };
    }

    const baseErr = (result && result.error) ? result.error : 'Senha incorreta.';
    if (cachedPortalStatus && cachedPortalStatus.whatsapp_notificar_falha) {
      const ipDisp = cachedIpInfo ? cachedIpInfo.ip : '0.0.0.0';
      const dev = getClientDeviceInfo();
      sendWhatsAppAlert(
        `⚠️ *SUBINOVA · TENTATIVA NEGADA*\n` +
        `━━━━━━━━━━━━━━━━━━━━\n` +
        `🔑 *Chave Tentada:* ${password}\n` +
        `🚫 *Motivo:* ${baseErr}\n` +
        `🌐 *IP:* ${ipDisp}\n` +
        `💻 *Dispositivo:* ${dev.os} · ${dev.browser}`
      );
    }

    if (baseErr === 'Senha incorreta.') {
      return { ok: false, error: `Senha incorreta. (${afterFail.attempts}/${Security.MAX_ATTEMPTS} tentativas)` };
    }
    return { ok: false, error: baseErr };
  }

  /* ==========================================================================
     MARCA D'ÁGUA DINÂMICA (ANTI-PRINT / ANTI-FOTO)
     ========================================================================== */
  function renderWatermark(rotulo, ip) {
    const wmContainer = document.getElementById('pbi-watermark');
    if (!wmContainer) return;
    wmContainer.innerHTML = '';
    const now = new Date();
    const dateStr = now.toLocaleDateString('pt-BR') + ' ' + now.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });

    for (let i = 0; i < 32; i++) {
      const item = document.createElement('div');
      item.className = 'watermark-item';
      item.innerHTML = `
        <span class="wm-label">${rotulo || 'SUBINOVA'}</span>
        <span class="wm-ip">${ip || '0.0.0.0'}</span>
        <span class="wm-time">${dateStr}</span>
      `;
      wmContainer.appendChild(item);
    }
  }

  /* ==========================================================================
     GERENCIAMENTO DE SESSÃO INTELIGENTE (5 MIN / VIP CHEFIA)
     ========================================================================== */
  let sessionTimerId = null;
  let warningTimerId = null;
  let countdownIntervalId = null;

  function expireSession() {
    if (pbiIframe) {
      pbiIframe.src = 'about:blank';
    }
    window.location.reload();
  }

  function setupSessionTimer(sessaoIlimitada) {
    if (sessionTimerId) clearTimeout(sessionTimerId);
    if (warningTimerId) clearTimeout(warningTimerId);
    if (countdownIntervalId) clearInterval(countdownIntervalId);

    if (sessaoIlimitada) {
      console.log('Sessão Contínua (Chefia/VIP) ativa. Sem expiração periódica.');
      return;
    }

    // Sessão de 5 minutos (300 segundos). Alerta abre com 45 segundos restantes (255s).
    const TOTAL_SESSION_MS = 5 * 60 * 1000;
    const WARNING_TIME_MS = 4 * 60 * 1000 + 15 * 1000;

    warningTimerId = setTimeout(() => {
      openSessionRenewModal();
    }, WARNING_TIME_MS);

    sessionTimerId = setTimeout(() => {
      expireSession();
    }, TOTAL_SESSION_MS);
  }

  function openSessionRenewModal() {
    const renewModal = document.getElementById('session-renew-modal');
    const renewInput = document.getElementById('renew-password-input');
    const renewTimerEl = document.getElementById('renew-countdown-timer');
    const renewErr = document.getElementById('renew-error');

    if (!renewModal) return;
    renewModal.classList.remove('hidden');
    if (renewInput) {
      renewInput.value = '';
      renewInput.focus();
    }
    if (renewErr) renewErr.classList.remove('visible');

    let secondsRemaining = 45;
    if (renewTimerEl) renewTimerEl.textContent = `${secondsRemaining}s`;

    countdownIntervalId = setInterval(() => {
      secondsRemaining--;
      if (renewTimerEl) {
        renewTimerEl.textContent = `${secondsRemaining}s`;
      }
      if (secondsRemaining <= 0) {
        clearInterval(countdownIntervalId);
        expireSession();
      }
    }, 1000);
  }

  function closeSessionRenewModal() {
    const renewModal = document.getElementById('session-renew-modal');
    if (renewModal) renewModal.classList.add('hidden');
    if (countdownIntervalId) clearInterval(countdownIntervalId);
  }

  async function handleAuthSuccess(authData) {
    const pbiUrl = typeof authData === 'string' ? authData : authData?.pbi_url;
    const rotulo = authData?.rotulo || 'SUBINOVA';
    const ip = authData?.ip || '0.0.0.0';
    const sessaoIlimitada = Boolean(authData?.sessao_ilimitada);

    if (btnSkipVideo) {
      btnSkipVideo.classList.add('hidden');
    }

    if (pbiIframe && pbiUrl) {
      pbiIframe.src = pbiUrl;
    }

    // Aplica a marca d'água
    renderWatermark(rotulo, ip);

    authModal.style.transition = 'opacity 0.4s ease';
    authModal.style.opacity = '0';
    if (bgVideo) {
      bgVideo.classList.add('fade-out');
    }

    setTimeout(() => {
      authModal.classList.add('hidden');
      if (bgVideo) {
        bgVideo.style.display = 'none';
      }
      pbiLayer.classList.add('active');
    }, 400);

    // Notificação em tempo real no WhatsApp
    const dispatchSuccessWpp = () => {
      if (cachedPortalStatus && cachedPortalStatus.whatsapp_notificar_sucesso) {
        const now = new Date();
        const dateStr = now.toLocaleDateString('pt-BR') + ' às ' + now.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
        const ipDisp = ip || (cachedIpInfo ? cachedIpInfo.ip : '0.0.0.0');
        const locDisp = cachedIpInfo && cachedIpInfo.cidade && cachedIpInfo.cidade !== 'N/A' 
          ? `${cachedIpInfo.cidade}, ${cachedIpInfo.regiao || 'BR'}`
          : 'Brasil';
        const dev = getClientDeviceInfo();

        const msg = `🚨 *SUBINOVA · NOVO ACESSO*\n` +
          `━━━━━━━━━━━━━━━━━━━━\n` +
          `👤 *Destinatário:* ${rotulo || 'SUBINOVA'}\n` +
          `🔑 *Chave:* ${lastAttemptedKey || 'Link de 1-Clique'}\n` +
          `📍 *Local:* ${locDisp}\n` +
          `🌐 *IP:* ${ipDisp}\n` +
          `💻 *Dispositivo:* ${dev.os} · ${dev.browser}\n` +
          `⏱️ *Sessão:* ${sessaoIlimitada ? '👑 Ilimitada (Chefia)' : '5 minutos'}\n` +
          `📅 *Horário:* ${dateStr}\n` +
          `━━━━━━━━━━━━━━━━━━━━\n` +
          `Status: ✅ Liberado com Sucesso`;

        sendWhatsAppAlert(msg);
      }
    };

    if (!cachedPortalStatus) {
      KeyStore.fetchPortalStatus().then(st => {
        cachedPortalStatus = st;
        dispatchSuccessWpp();
      }).catch(() => {});
    } else {
      dispatchSuccessWpp();
    }

    // Inicia temporizador inteligente de sessão
    setupSessionTimer(sessaoIlimitada);
  }

  function handleAuthError(msg) {
    if (authErrorText && msg) {
      authErrorText.textContent = msg;
    }
    authError.classList.add('visible');
    authCard.classList.remove('shake');
    void authCard.offsetWidth;
    authCard.classList.add('shake');
    passwordInput.focus();
    passwordInput.select();
  }

  async function trySubmit() {
    const val = passwordInput.value.trim();
    if (!val) return;
    const submitBtn = document.getElementById('btn-auth-submit');
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Verificando...';
    }
    try {
      const res = await validateAccessKey(val);
      if (res.ok) {
        handleAuthSuccess(res);
      } else if (res.error) {
        handleAuthError(res.error);
      }
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Acessar Painel';
      }
    }
  }

  /* ==========================================================================
     EVENTOS
     ========================================================================== */
  if (pbiIframe) {
    pbiIframe.addEventListener('load', () => {
      if (pbiIframe.src && pbiIframe.src !== 'about:blank' && pbiLoading) {
        pbiLoading.classList.add('hidden');
      }
    });
  }

  if (btnSkipVideo) {
    btnSkipVideo.addEventListener('click', (e) => {
      e.stopPropagation();
      showAuthModal();
    });
  }

  /* ==========================================================================
     PROTEÇÃO ANTI-DEVTOOLS & KILL-SWITCH DE SEGURANÇA
     ========================================================================== */
  function triggerSecurityLockout() {
    if (isDevToolsTriggered) return;
    isDevToolsTriggered = true;

    // Descarrega imediatamente o Power BI para about:blank
    if (pbiIframe) {
      pbiIframe.src = 'about:blank';
    }
    if (pbiLayer) {
      pbiLayer.classList.remove('active');
    }

    // Exibe o modal de segurança
    if (securityAlertModal) {
      securityAlertModal.classList.remove('hidden');
    }

    // Alerta de segurança no WhatsApp
    const dispatchDevToolsWpp = () => {
      if (cachedPortalStatus && cachedPortalStatus.whatsapp_notificar_devtools) {
        const ipDisp = cachedIpInfo ? cachedIpInfo.ip : '0.0.0.0';
        const dev = getClientDeviceInfo();
        const msg = `🚨 *SUBINOVA · ALERTA DE SEGURANÇA*\n` +
          `━━━━━━━━━━━━━━━━━━━━\n` +
          `⚠️ *Tentativa de Inspeção de Código (F12 / DevTools)!*\n` +
          `🌐 *IP:* ${ipDisp}\n` +
          `💻 *Dispositivo:* ${dev.os} · ${dev.browser}\n` +
          `🔒 O painel Power BI foi descarregado instantaneamente.`;
        sendWhatsAppAlert(msg);
      }
    };

    if (!cachedPortalStatus) {
      KeyStore.fetchPortalStatus().then(st => {
        cachedPortalStatus = st;
        dispatchDevToolsWpp();
      }).catch(() => {});
    } else {
      dispatchDevToolsWpp();
    }
  }

  if (btnSecurityReload) {
    btnSecurityReload.addEventListener('click', () => {
      window.location.reload();
    });
  }

  // 1. Bloqueia clique com botão direito na página inteira
  window.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    return false;
  }, true);

  // 2. Bloqueia atalhos de teclado de inspeção e código-fonte
  window.addEventListener('keydown', (e) => {
    // Mantém o atalho do ADM (Ctrl+Shift+A) funcionando
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
      e.preventDefault();
      window.location.href = 'admin.html';
      return;
    }

    // F12
    if (e.key === 'F12' || e.keyCode === 123) {
      e.preventDefault();
      e.stopPropagation();
      triggerSecurityLockout();
      return false;
    }

    // Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C (DevTools / Console / Inspector)
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && ['I', 'i', 'J', 'j', 'C', 'c'].includes(e.key)) {
      e.preventDefault();
      e.stopPropagation();
      triggerSecurityLockout();
      return false;
    }

    // Ctrl+U (Ver código-fonte) e Ctrl+S (Salvar página completa)
    if ((e.ctrlKey || e.metaKey) && ['U', 'u', 'S', 's'].includes(e.key)) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }

    // Abertura do modal ao pressionar qualquer tecla antes de abrir
    if (!modalOpened && !e.ctrlKey && !e.metaKey && !e.altKey) {
      showAuthModal();
    }
  }, true);

  // 3. Monitor contínuo do DevTools acoplado à janela
  setInterval(() => {
    if (isDevToolsTriggered) return;
    const widthDiff = window.outerWidth - window.innerWidth;
    const heightDiff = window.outerHeight - window.innerHeight;
    if (widthDiff > 180 || heightDiff > 180) {
      if (pbiLayer && pbiLayer.classList.contains('active')) {
        triggerSecurityLockout();
      }
    }
  }, 700);

  window.addEventListener('click', () => {
    if (!modalOpened) {
      showAuthModal();
    }
  });

  if (bgVideo) {
    bgVideo.addEventListener('ended', showAuthModal);
    bgVideo.addEventListener('error', showAuthModal);
    bgVideo.addEventListener('stalled', showAuthModal);

    setTimeout(() => {
      if (!modalOpened) {
        showAuthModal();
      }
    }, 4200);
  }

  passwordInput.addEventListener('input', () => {
    authError.classList.remove('visible');
  });

  authForm.addEventListener('submit', (e) => {
    e.preventDefault();
    trySubmit();
  });

  btnToggleEye.addEventListener('click', () => {
    const isPass = passwordInput.type === 'password';
    passwordInput.type = isPass ? 'text' : 'password';
    btnToggleEye.innerHTML = isPass
      ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
           <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
           <line x1="1" y1="1" x2="23" y2="23"/>
         </svg>`
      : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
           <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
           <circle cx="12" cy="12" r="3"/>
         </svg>`;
  });

  /* ==========================================================================
     RENOVAÇÃO DE SESSÃO & MODO APRESENTAÇÃO / TELA CHEIA
     ========================================================================== */
  const renewForm = document.getElementById('renew-form');
  const renewPasswordInput = document.getElementById('renew-password-input');
  const renewError = document.getElementById('renew-error');
  const renewErrorText = document.getElementById('renew-error-text');
  const btnRenewSubmit = document.getElementById('btn-renew-submit');
  const btnRenewLogout = document.getElementById('btn-renew-logout');

  if (renewForm) {
    renewForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const val = renewPasswordInput.value.trim();
      if (!val) return;
      if (btnRenewSubmit) {
        btnRenewSubmit.disabled = true;
        btnRenewSubmit.textContent = 'Verificando...';
      }
      try {
        const res = await validateAccessKey(val);
        if (res.ok) {
          closeSessionRenewModal();
          setupSessionTimer(res.sessao_ilimitada);
        } else {
          if (renewError && renewErrorText) {
            renewErrorText.textContent = res.error || 'Senha incorreta.';
            renewError.classList.add('visible');
          }
          renewPasswordInput.focus();
          renewPasswordInput.select();
        }
      } finally {
        if (btnRenewSubmit) {
          btnRenewSubmit.disabled = false;
          btnRenewSubmit.textContent = 'Permanecer Conectado';
        }
      }
    });
  }

  if (renewPasswordInput) {
    renewPasswordInput.addEventListener('input', () => {
      if (renewError) renewError.classList.remove('visible');
    });
  }

  if (btnRenewLogout) {
    btnRenewLogout.addEventListener('click', () => {
      expireSession();
    });
  }

  const btnFullscreenToggle = document.getElementById('btn-fullscreen-toggle');
  if (btnFullscreenToggle) {
    btnFullscreenToggle.addEventListener('click', () => {
      if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().catch(() => {});
        const span = btnFullscreenToggle.querySelector('span');
        if (span) span.textContent = 'Sair da Tela Cheia';
      } else {
        if (document.exitFullscreen) {
          document.exitFullscreen().catch(() => {});
          const span = btnFullscreenToggle.querySelector('span');
          if (span) span.textContent = 'Tela Cheia';
        }
      }
    });

    document.addEventListener('fullscreenchange', () => {
      const span = btnFullscreenToggle.querySelector('span');
      if (!document.fullscreenElement && span) {
        span.textContent = 'Tela Cheia';
      }
    });
  }

  /* ==========================================================================
     STARTUP & LINK DE 1 CLIQUE
     ========================================================================== */
  window.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const directKey = urlParams.get('k');

    // Link de 1-clique gerado pelo ADM (?k=...)
    if (directKey) {
      try {
        // Remove a chave imediatamente da barra de endereço para não ficar no histórico
        const cleanUrl = window.location.pathname;
        window.history.replaceState({}, document.title, cleanUrl);
      } catch (e) {}

      if (bgVideo) {
        try { bgVideo.pause(); } catch (e) {}
        bgVideo.style.display = 'none';
      }
      if (btnSkipVideo) btnSkipVideo.classList.add('hidden');

      (async () => {
        const res = await validateAccessKey(directKey);
        if (res.ok) {
          handleAuthSuccess(res);
        } else {
          showAuthModal();
          handleAuthError(res.error || 'Chave de acesso do link inválida ou expirada.');
        }
      })();
      return;
    }

    if (urlParams.get('preview') === 'modal') {
      showAuthModal();
      return;
    }

    if (bgVideo) {
      const playPromise = bgVideo.play();
      if (playPromise !== undefined) {
        playPromise.catch(() => {
          showAuthModal();
        });
      }
    } else {
      showAuthModal();
    }
  });

})();
