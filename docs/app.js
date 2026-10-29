(function () {
  'use strict';

  // Configurações e Chaves Padrão
  const DEFAULT_HASH = "0257caf28e46a4c150cad95f28fa4bf0d2c2183d2eb2ad61be1d76d35136ca24"; // @3293
  const LOCAL_STORAGE_KEYS = 'subinova_chaves_acesso';
  const LOCAL_STORAGE_CLOUD = 'subinova_cloud_config';

  // Elementos do DOM
  const pbiLayer = document.getElementById('pbi-layer');
  const bgVideo = document.getElementById('bg-video');
  const authModal = document.getElementById('auth-modal');
  const authForm = document.getElementById('auth-form');
  const passwordInput = document.getElementById('password-input');
  const btnToggleEye = document.getElementById('btn-toggle-eye');
  const authError = document.getElementById('auth-error');
  const authErrorText = document.getElementById('auth-error-text');
  const authCard = document.querySelector('.auth-card');

  let modalOpened = false;

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
     CAMADA DE VALIDAÇÃO (NUVEM / LOCALSTORAGE)
     ========================================================================== */
  const KeyStore = {
    getCloudConfig() {
      try {
        return JSON.parse(localStorage.getItem(LOCAL_STORAGE_CLOUD)) || null;
      } catch (e) {
        return null;
      }
    },

    async isMaintenanceActive() {
      const cfg = this.getCloudConfig();
      if (cfg && cfg.url && cfg.key) {
        try {
          const res = await fetch(`${cfg.url}/rest/v1/configuracoes?chave=eq.modo_manutencao&select=valor`, {
            headers: { 'apikey': cfg.key, 'Authorization': `Bearer ${cfg.key}` }
          });
          if (res.ok) {
            const data = await res.json();
            if (data.length) return data[0].valor === 'true';
          }
        } catch (e) {
          console.warn('Erro ao checar manutenção na nuvem:', e);
        }
      }
      return localStorage.getItem('subinova_modo_manutencao') === 'true';
    },

    async fetchAllKeys() {
      const cfg = this.getCloudConfig();
      if (cfg && cfg.url && cfg.key) {
        try {
          const res = await fetch(`${cfg.url}/rest/v1/chaves_acesso?select=*`, {
            headers: { 'apikey': cfg.key, 'Authorization': `Bearer ${cfg.key}` }
          });
          if (res.ok) {
            return await res.json();
          }
        } catch (e) {
          console.warn('Erro ao buscar chaves na nuvem, usando local:', e);
        }
      }

      // Local storage fallback
      const raw = localStorage.getItem(LOCAL_STORAGE_KEYS);
      if (raw) {
        try {
          return JSON.parse(raw);
        } catch (e) {}
      }

      // Fallback padrão se não houver chaves salvas
      return [{
        id: 'key-default',
        chave: '@3293',
        chave_hash: DEFAULT_HASH,
        rotulo: 'Padrão',
        ativa: true,
        total_usos: 0
      }];
    },

    async recordUsage(keyItem) {
      if (!keyItem) return;
      const now = new Date().toISOString();
      const newTotal = (keyItem.total_usos || 0) + 1;

      // Se nuvem:
      const cfg = this.getCloudConfig();
      if (cfg && cfg.url && cfg.key && keyItem.id) {
        fetch(`${cfg.url}/rest/v1/chaves_acesso?id=eq.${keyItem.id}`, {
          method: 'PATCH',
          headers: {
            'apikey': cfg.key,
            'Authorization': `Bearer ${cfg.key}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ total_usos: newTotal, ultimo_acesso: now })
        }).catch(() => {});
      }

      // Se local:
      try {
        const raw = localStorage.getItem(LOCAL_STORAGE_KEYS);
        if (raw) {
          const keys = JSON.parse(raw);
          const k = keys.find(item => item.id === keyItem.id || item.chave === keyItem.chave);
          if (k) {
            k.total_usos = newTotal;
            k.ultimo_acesso = now;
            localStorage.setItem(LOCAL_STORAGE_KEYS, JSON.stringify(keys));
          }
        }
      } catch (e) {}
    }
  };

  /* ==========================================================================
     ABERTURA DO MODAL DE AUTENTICAÇÃO
     ========================================================================== */
  function showAuthModal() {
    if (modalOpened) return;
    modalOpened = true;

    if (bgVideo) {
      bgVideo.classList.add('dimmed');
    }

    authModal.classList.remove('hidden');
    passwordInput.value = '';
    authError.classList.remove('visible');
    passwordInput.focus();
  }

  /* ==========================================================================
     VALIDAÇÃO DA SENHA & LIBERAÇÃO IMEDIATA DO POWER BI
     ========================================================================== */
  async function validateAccessKey(password) {
    if (!password) return { ok: false, error: 'Digite uma senha.' };

    // 1. Checa se o painel está em manutenção
    const inMaintenance = await KeyStore.isMaintenanceActive();
    if (inMaintenance) {
      return { ok: false, error: 'Painel em manutenção temporária. Tente mais tarde.' };
    }

    const hash = await computeSHA256(password);
    const keys = await KeyStore.fetchAllKeys();

    // 2. Busca a chave correspondente (por texto exato ou hash SHA-256)
    const match = keys.find(k => k.chave === password || k.chave_hash === hash);

    if (match) {
      if (!match.ativa) {
        return { ok: false, error: 'Esta chave de acesso foi desativada ou revogada.' };
      }
      KeyStore.recordUsage(match);
      return { ok: true };
    }

    // 3. Fallback de emergência (@3293) caso a lista do banco esteja vazia
    if (hash === DEFAULT_HASH) {
      return { ok: true };
    }

    return { ok: false, error: 'Senha incorreta. Tente novamente.' };
  }

  async function handleAuthSuccess() {
    // Fade out no modal e no vídeo
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
      // Power BI surge 100% visível e interativo
      pbiLayer.classList.add('active');
    }, 400);
  }

  function handleAuthError(msg) {
    if (authErrorText && msg) {
      authErrorText.textContent = msg;
    }
    authError.classList.add('visible');
    authCard.classList.remove('shake');
    void authCard.offsetWidth; // trigger reflow
    authCard.classList.add('shake');
    passwordInput.focus();
    passwordInput.select();
  }

  async function trySubmit() {
    const val = passwordInput.value.trim();
    if (!val) return;
    const res = await validateAccessKey(val);
    if (res.ok) {
      handleAuthSuccess();
    } else {
      handleAuthError(res.error);
    }
  }

  /* ==========================================================================
     EVENTOS
     ========================================================================== */

  // 1. Quando o vídeo de 4s termina -> abre a tela de senha automaticamente
  if (bgVideo) {
    bgVideo.addEventListener('ended', showAuthModal);

    // Fallback de segurança: caso o vídeo demore (~4.2s)
    setTimeout(() => {
      if (!modalOpened) {
        showAuthModal();
      }
    }, 4200);
  }

  // 2. Validação instantânea ao digitar
  let inputTimer = null;
  passwordInput.addEventListener('input', () => {
    authError.classList.remove('visible');
    const val = passwordInput.value.trim();
    
    // Se o usuário já digitou 4 ou mais caracteres, verifica silenciosamente se é uma chave válida
    clearTimeout(inputTimer);
    if (val.length >= 4) {
      inputTimer = setTimeout(async () => {
        const res = await validateAccessKey(val);
        if (res.ok) {
          handleAuthSuccess();
        }
      }, 150);
    }
  });

  // 3. Validação ao pressionar Enter
  authForm.addEventListener('submit', (e) => {
    e.preventDefault();
    trySubmit();
  });

  // 4. Mostrar / Ocultar Senha
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

  // 5. Atalho de Teclado Global: Ctrl + Shift + A para abrir Painel ADM
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
      e.preventDefault();
      window.location.href = 'admin.html';
    }
  });

  /* ==========================================================================
     STARTUP: Tenta reproduzir o vídeo em tela cheia imediatamente
     ========================================================================== */
  window.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('preview') === 'modal') {
      showAuthModal();
      return;
    }
    if (urlParams.get('preview') === 'pbi') {
      handleAuthSuccess();
      return;
    }

    if (bgVideo) {
      bgVideo.play().catch(() => {
        setTimeout(showAuthModal, 1500);
      });
    }
  });

})();