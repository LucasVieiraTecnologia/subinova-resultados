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
              banner_mensagem: data.banner_mensagem || ''
            };
          }
        } catch (e) {}
      }
      return {
        modo_manutencao: localStorage.getItem('subinova_modo_manutencao') === 'true',
        mensagem_manutencao: 'Painel em manutenção temporária.',
        banner_ativo: localStorage.getItem('subinova_banner_ativo') === 'true',
        banner_mensagem: localStorage.getItem('subinova_banner_msg') || ''
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
      return { ok: true, pbi_url: '' };
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
     VALIDAÇÃO DA SENHA & LIBERAÇÃO DO POWER BI
     ========================================================================== */
  async function validateAccessKey(password) {
    if (!password) return { ok: false, error: 'Digite uma senha.' };

    const sec = Security.getState();
    if (sec.isLocked) {
      return { ok: false, error: 'Acesso temporariamente bloqueado por excesso de tentativas.' };
    }

    const result = await KeyStore.validateServerSide(password, true);

    if (result && result.ok) {
      Security.reset();
      return { ok: true, pbi_url: result.pbi_url };
    }

    const afterFail = Security.recordFailure();
    if (afterFail.isLocked || (result && result.locked)) {
      const lockUntil = afterFail.lockedUntil || (Date.now() + Security.LOCK_DURATION_MS);
      startLockoutCountdown(lockUntil);
      return { ok: false, error: (result && result.error) || 'Limite de 5 tentativas atingido. Bloqueado por 3 minutos.' };
    }

    const baseErr = (result && result.error) ? result.error : 'Senha incorreta.';
    if (baseErr === 'Senha incorreta.') {
      return { ok: false, error: `Senha incorreta. (${afterFail.attempts}/${Security.MAX_ATTEMPTS} tentativas)` };
    }
    return { ok: false, error: baseErr };
  }

  async function handleAuthSuccess(pbiUrl) {
    if (btnSkipVideo) {
      btnSkipVideo.classList.add('hidden');
    }

    if (pbiIframe && pbiUrl) {
      pbiIframe.src = pbiUrl;
    }

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

    // Sessão com expiração automática a cada 5 minutos (F5 forçado para exigir novo login)
    const SESSION_TIMEOUT_MS = 5 * 60 * 1000;
    setTimeout(() => {
      if (pbiIframe) {
        pbiIframe.src = 'about:blank';
      }
      window.location.reload();
    }, SESSION_TIMEOUT_MS);
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
        handleAuthSuccess(res.pbi_url);
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
     STARTUP
     ========================================================================== */
  window.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
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
