(function () {
  'use strict';

  // Configuração padrão
  const DEFAULT_ADMIN_HASH = 'e306389b1195c6e87ed86d733e290d9ab54864ad313ab6424b3fa72b6a2a6e9b'; // @admin3293
  const LOCAL_STORAGE_KEYS = 'subinova_chaves_acesso';
  const LOCAL_STORAGE_CONFIG = 'subinova_portal_config';
  const LOCAL_STORAGE_CLOUD = 'subinova_cloud_config';

  // Chaves iniciais padrão se não houver nada no banco/localStorage
  const INITIAL_KEYS = [
    {
      id: 'key-1',
      chave: '@3293',
      chave_hash: '0257caf28e46a4c150cad95f28fa4bf0d2c2183d2eb2ad61be1d76d35136ca24',
      rotulo: 'Chave Geral Padrão',
      ativa: true,
      criada_em: new Date().toISOString(),
      ultimo_acesso: null,
      total_usos: 0
    }
  ];

  /* ==========================================================================
     ALGORITMO SHA-256
     ========================================================================== */
  function sha256Sync(ascii) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var result = '';
    var words = [];
    var asciiBitLength = ascii.length * 8;
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
    for (var i = 0; i < ascii.length; i++) {
      var code = ascii.charCodeAt(i);
      if (code < 128) composite.push(code);
      else if (code < 2048) composite.push((code >> 6) | 192, (code & 63) | 128);
      else composite.push((code >> 12) | 224, ((code >> 6) & 63) | 128, (code & 63) | 128);
    }
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
      for (var j = 0; j < 64; j++) {
        if (j < 16) w[j] = words[i + j];
        else {
          var gamma0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
          var gamma1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
          w[j] = (w[j - 16] + gamma0 + w[j - 7] + gamma1) >>> 0;
        }
        var ch = (e & f) ^ (~e & g);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        var s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        var t1 = (h + s1 + ch + k[j] + w[j]) >>> 0;
        var t2 = (s0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      hash[0] = (hash[0] + a) >>> 0; hash[1] = (hash[1] + b) >>> 0;
      hash[2] = (hash[2] + c) >>> 0; hash[3] = (hash[3] + d) >>> 0;
      hash[4] = (hash[4] + e) >>> 0; hash[5] = (hash[5] + f) >>> 0;
      hash[6] = (hash[6] + g) >>> 0; hash[7] = (hash[7] + h) >>> 0;
    }
    for (i = 0; i < 8; i++) {
      for (j = 3; j >= 0; j--) {
        var byteVal = (hash[i] >> (j * 8)) & 255;
        result += (byteVal < 16 ? '0' : '') + byteVal.toString(16);
      }
    }
    return result;
  }

  async function computeSHA256(text) {
    if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
      try {
        const msgBuffer = new TextEncoder().encode(text);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (e) {
        return sha256Sync(text);
      }
    }
    return sha256Sync(text);
  }

  /* ==========================================================================
     CAMADA DE DADOS & NUVEM (SUPABASE / LOCALSTORAGE)
     ========================================================================== */
  const Storage = {
    getCloudConfig() {
      try {
        return JSON.parse(localStorage.getItem(LOCAL_STORAGE_CLOUD)) || null;
      } catch (e) {
        return null;
      }
    },

    setCloudConfig(cfg) {
      if (!cfg) localStorage.removeItem(LOCAL_STORAGE_CLOUD);
      else localStorage.setItem(LOCAL_STORAGE_CLOUD, JSON.stringify(cfg));
    },

    isCloudEnabled() {
      const cfg = this.getCloudConfig();
      return !!(cfg && cfg.url && cfg.key);
    },

    async fetchKeys() {
      if (this.isCloudEnabled()) {
        const cfg = this.getCloudConfig();
        try {
          const res = await fetch(`${cfg.url}/rest/v1/chaves_acesso?select=*&order=criada_em.desc`, {
            headers: {
              'apikey': cfg.key,
              'Authorization': `Bearer ${cfg.key}`
            }
          });
          if (res.ok) {
            const data = await res.json();
            return data;
          }
        } catch (e) {
          console.warn('Erro ao conectar ao Supabase, caindo para modo local:', e);
        }
      }

      // Modo Local (LocalStorage)
      const raw = localStorage.getItem(LOCAL_STORAGE_KEYS);
      if (!raw) {
        localStorage.setItem(LOCAL_STORAGE_KEYS, JSON.stringify(INITIAL_KEYS));
        return INITIAL_KEYS;
      }
      try {
        return JSON.parse(raw);
      } catch (e) {
        return INITIAL_KEYS;
      }
    },

    async saveKey(item) {
      if (this.isCloudEnabled()) {
        const cfg = this.getCloudConfig();
        const res = await fetch(`${cfg.url}/rest/v1/chaves_acesso`, {
          method: 'POST',
          headers: {
            'apikey': cfg.key,
            'Authorization': `Bearer ${cfg.key}`,
            'Content-Type': 'application/json',
            'Prefer': 'resolution=merge-duplicates'
          },
          body: JSON.stringify(item)
        });
        if (!res.ok) throw new Error('Falha ao salvar chave na nuvem.');
        return;
      }

      const keys = await this.fetchKeys();
      const idx = keys.findIndex(k => k.id === item.id || k.chave === item.chave);
      if (idx >= 0) keys[idx] = { ...keys[idx], ...item };
      else keys.unshift(item);
      localStorage.setItem(LOCAL_STORAGE_KEYS, JSON.stringify(keys));
    },

    async toggleKeyStatus(id, newStatus) {
      if (this.isCloudEnabled()) {
        const cfg = this.getCloudConfig();
        const res = await fetch(`${cfg.url}/rest/v1/chaves_acesso?id=eq.${id}`, {
          method: 'PATCH',
          headers: {
            'apikey': cfg.key,
            'Authorization': `Bearer ${cfg.key}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ ativa: newStatus })
        });
        if (!res.ok) throw new Error('Erro ao alterar status na nuvem.');
        return;
      }

      const keys = await this.fetchKeys();
      const k = keys.find(item => item.id === id);
      if (k) {
        k.ativa = newStatus;
        localStorage.setItem(LOCAL_STORAGE_KEYS, JSON.stringify(keys));
      }
    },

    async deleteKey(id) {
      if (this.isCloudEnabled()) {
        const cfg = this.getCloudConfig();
        const res = await fetch(`${cfg.url}/rest/v1/chaves_acesso?id=eq.${id}`, {
          method: 'DELETE',
          headers: {
            'apikey': cfg.key,
            'Authorization': `Bearer ${cfg.key}`
          }
        });
        if (!res.ok) throw new Error('Erro ao excluir na nuvem.');
        return;
      }

      let keys = await this.fetchKeys();
      keys = keys.filter(k => k.id !== id);
      localStorage.setItem(LOCAL_STORAGE_KEYS, JSON.stringify(keys));
    },

    async getMaintenanceMode() {
      if (this.isCloudEnabled()) {
        const cfg = this.getCloudConfig();
        try {
          const res = await fetch(`${cfg.url}/rest/v1/configuracoes?chave=eq.modo_manutencao&select=valor`, {
            headers: { 'apikey': cfg.key, 'Authorization': `Bearer ${cfg.key}` }
          });
          if (res.ok) {
            const data = await res.json();
            if (data.length) return data[0].valor === 'true';
          }
        } catch (e) {}
      }
      return localStorage.getItem('subinova_modo_manutencao') === 'true';
    },

    async setMaintenanceMode(val) {
      if (this.isCloudEnabled()) {
        const cfg = this.getCloudConfig();
        await fetch(`${cfg.url}/rest/v1/configuracoes`, {
          method: 'POST',
          headers: {
            'apikey': cfg.key,
            'Authorization': `Bearer ${cfg.key}`,
            'Content-Type': 'application/json',
            'Prefer': 'resolution=merge-duplicates'
          },
          body: JSON.stringify({ chave: 'modo_manutencao', valor: String(val) })
        });
      }
      localStorage.setItem('subinova_modo_manutencao', String(val));
    },

    getAdminHash() {
      const stored = localStorage.getItem('subinova_admin_hash');
      if (!stored || stored === '1097e8b623cf5ab862c95359b35e0762cf39b4b0df16ff1a051515ef50b1069f') {
        return DEFAULT_ADMIN_HASH;
      }
      return stored;
    },

    setAdminHash(h) {
      localStorage.setItem('subinova_admin_hash', h);
    }
  };

  /* ==========================================================================
     ELEMENTOS DOM
     ========================================================================== */
  const loginScreen = document.getElementById('admin-login-screen');
  const dashScreen = document.getElementById('admin-dashboard-screen');
  const adminPassInput = document.getElementById('admin-pass');
  const adminToggleEye = document.getElementById('admin-toggle-eye');
  const adminLoginError = document.getElementById('admin-login-error');
  const adminLoginForm = document.getElementById('admin-login-form');
  const btnAdminLogout = document.getElementById('btn-admin-logout');

  const syncBadge = document.getElementById('sync-status-badge');
  const syncText = document.getElementById('sync-status-text');

  const kpiTotal = document.getElementById('kpi-total-keys');
  const kpiActive = document.getElementById('kpi-active-keys');
  const kpiBlocked = document.getElementById('kpi-blocked-keys');
  const kpiMaintenance = document.getElementById('kpi-maintenance-status');
  const chkMaintenance = document.getElementById('chk-maintenance');

  const keysTableBody = document.getElementById('keys-table-body');
  const btnOpenNewKey = document.getElementById('btn-open-new-key');
  const btnOpenCloud = document.getElementById('btn-open-cloud-config');
  const btnOpenAdminPass = document.getElementById('btn-open-change-admin-pass');

  // Modais
  const modalKey = document.getElementById('modal-key');
  const formKey = document.getElementById('form-key');
  const keyInputVal = document.getElementById('key-input-val');
  const keyInputLabel = document.getElementById('key-input-label');
  const keyInputActive = document.getElementById('key-input-active');
  const btnGenerateKey = document.getElementById('btn-generate-key');

  const modalCloud = document.getElementById('modal-cloud');
  const formCloud = document.getElementById('form-cloud');
  const cloudUrl = document.getElementById('cloud-url');
  const cloudKey = document.getElementById('cloud-key');
  const btnTestCloud = document.getElementById('btn-test-cloud');
  const btnDisconnectCloud = document.getElementById('btn-disconnect-cloud');
  const cloudFeedback = document.getElementById('cloud-test-feedback');

  const modalAdminPass = document.getElementById('modal-admin-pass');
  const formAdminPass = document.getElementById('form-admin-pass');
  const newAdminPass = document.getElementById('new-admin-pass');
  const confirmAdminPass = document.getElementById('confirm-admin-pass');
  const adminPassError = document.getElementById('admin-pass-error');

  /* ==========================================================================
     AUTENTICAÇÃO DO ADMINISTRADOR
     ========================================================================== */
  async function checkAdminLogin() {
    const val = adminPassInput.value.trim();
    if (!val) return;

    // 1. Suporte direto à chave padrão master
    if (val === '@admin3293') {
      sessionStorage.setItem('subinova_admin_logged', '1');
      adminLoginError.classList.remove('visible');
      showDashboard();
      return;
    }

    // 2. Validação criptográfica SHA-256
    const h = await computeSHA256(val);
    const expected = Storage.getAdminHash();
    if (h === expected || h === DEFAULT_ADMIN_HASH) {
      sessionStorage.setItem('subinova_admin_logged', '1');
      adminLoginError.classList.remove('visible');
      showDashboard();
    } else {
      adminLoginError.classList.add('visible');
      adminPassInput.focus();
    }
  }

  function showDashboard() {
    loginScreen.classList.add('hidden');
    dashScreen.classList.remove('hidden');
    updateCloudStatusUI();
    renderDashboard();
  }

  function logout() {
    sessionStorage.removeItem('subinova_admin_logged');
    dashScreen.classList.add('hidden');
    loginScreen.classList.remove('hidden');
    adminPassInput.value = '';
    adminPassInput.focus();
  }

  adminLoginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    checkAdminLogin();
  });

  adminPassInput.addEventListener('input', () => {
    adminLoginError.classList.remove('visible');
    const val = adminPassInput.value.trim();
    if (val === '@admin3293') {
      checkAdminLogin();
    }
  });

  adminToggleEye.addEventListener('click', () => {
    const isPass = adminPassInput.type === 'password';
    adminPassInput.type = isPass ? 'text' : 'password';
  });

  btnAdminLogout.addEventListener('click', logout);

  /* ==========================================================================
     RENDERIZAÇÃO DO DASHBOARD
     ========================================================================== */
  function updateCloudStatusUI() {
    if (Storage.isCloudEnabled()) {
      syncBadge.classList.add('cloud-connected');
      syncText.textContent = 'Nuvem Conectada';
    } else {
      syncBadge.classList.remove('cloud-connected');
      syncText.textContent = 'Modo Local (Offline)';
    }
  }

  function formatDate(isoStr) {
    if (!isoStr) return 'Nunca';
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch (e) {
      return isoStr;
    }
  }

  async function renderDashboard() {
    const keys = await Storage.fetchKeys();
    const isMaint = await Storage.getMaintenanceMode();

    // Atualiza KPIs
    const total = keys.length;
    const active = keys.filter(k => k.ativa).length;
    const blocked = total - active;

    kpiTotal.textContent = total;
    kpiActive.textContent = active;
    kpiBlocked.textContent = blocked;

    chkMaintenance.checked = isMaint;
    kpiMaintenance.textContent = isMaint ? 'ATIVADO (Bloqueado)' : 'Desativado (Normal)';
    if (isMaint) {
      kpiMaintenance.classList.add('active-maintenance');
    } else {
      kpiMaintenance.classList.remove('active-maintenance');
    }

    // Renderiza Tabela
    keysTableBody.innerHTML = '';
    if (keys.length === 0) {
      keysTableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:#64748b;">Nenhuma chave cadastrada. Clique em "Criar Nova Chave" para começar.</td></tr>`;
      return;
    }

    keys.forEach((k) => {
      const tr = document.createElement('tr');
      const maskVal = '••••••••';
      const realVal = k.chave;

      tr.innerHTML = `
        <td>
          <span class="key-code" data-id="${k.id}">
            <span class="key-text">${maskVal}</span>
            <button type="button" class="btn-icon-reveal" title="Ver / Ocultar Chave" data-val="${realVal}">
              👁
            </button>
          </span>
        </td>
        <td><b class="key-label-text">${k.rotulo || 'Sem identificador'}</b></td>
        <td style="color:#94a3b8; font-size:12px;">${formatDate(k.criada_em)}</td>
        <td style="color:#94a3b8; font-size:12px;">${formatDate(k.ultimo_acesso)}</td>
        <td><span style="font-weight:600; color:#38bdf8;">${k.total_usos || 0}</span></td>
        <td>
          <span class="status-pill ${k.ativa ? 'active' : 'blocked'}">
            <span style="width:6px;height:6px;border-radius:50%;background:currentColor;"></span>
            ${k.ativa ? 'Ativa' : 'Bloqueada'}
          </span>
        </td>
        <td>
          <div class="row-actions">
            <button type="button" class="${k.ativa ? 'btn-table-block' : 'btn-table-activate'}" data-act="toggle" data-id="${k.id}" data-status="${k.ativa}">
              ${k.ativa ? '🚫 Bloquear' : '✅ Ativar'}
            </button>
            <button type="button" class="btn-table-delete" data-act="delete" data-id="${k.id}" title="Excluir Chave">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"/>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
              </svg>
            </button>
          </div>
        </td>
      `;

      keysTableBody.appendChild(tr);
    });

    attachTableEvents();
  }

  function attachTableEvents() {
    // Revelar / Ocultar Chave
    document.querySelectorAll('.btn-icon-reveal').forEach((btn) => {
      btn.onclick = () => {
        const textSpan = btn.parentElement.querySelector('.key-text');
        const real = btn.getAttribute('data-val');
        if (textSpan.textContent === '••••••••') {
          textSpan.textContent = real;
          btn.style.color = '#38bdf8';
        } else {
          textSpan.textContent = '••••••••';
          btn.style.color = '#64748b';
        }
      };
    });

    // Alternar Status (Bloquear / Ativar)
    document.querySelectorAll('[data-act="toggle"]').forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-id');
        const current = btn.getAttribute('data-status') === 'true';
        btn.textContent = 'Salvando...';
        btn.disabled = true;
        try {
          await Storage.toggleKeyStatus(id, !current);
          renderDashboard();
        } catch (e) {
          alert('Erro ao alterar status: ' + e.message);
          btn.disabled = false;
        }
      };
    });

    // Excluir Chave
    document.querySelectorAll('[data-act="delete"]').forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-id');
        if (confirm('Tem certeza que deseja excluir esta chave de acesso?')) {
          await Storage.deleteKey(id);
          renderDashboard();
        }
      };
    });
  }

  // Alternar Modo Manutenção
  chkMaintenance.addEventListener('change', async () => {
    const isMaint = chkMaintenance.checked;
    await Storage.setMaintenanceMode(isMaint);
    renderDashboard();
  });

  /* ==========================================================================
     GERENCIAMENTO DE MODAIS
     ========================================================================== */
  function openModal(el) { el.classList.remove('hidden'); }
  function closeModal(el) { el.classList.add('hidden'); }

  document.querySelectorAll('[data-close]').forEach((btn) => {
    btn.onclick = () => {
      const targetId = btn.getAttribute('data-close');
      closeModal(document.getElementById(targetId));
    };
  });

  // Modal: Nova Chave
  btnOpenNewKey.addEventListener('click', () => {
    keyInputVal.value = '';
    keyInputLabel.value = '';
    keyInputActive.checked = true;
    openModal(modalKey);
    keyInputVal.focus();
  });

  btnGenerateKey.addEventListener('click', () => {
    const randNum = Math.floor(1000 + Math.random() * 9000);
    const prefixes = ['@subinova', '@sede', '@acesso', '@minas', '@inova'];
    const p = prefixes[Math.floor(Math.random() * prefixes.length)];
    keyInputVal.value = `${p}${randNum}`;
  });

  formKey.addEventListener('submit', async (e) => {
    e.preventDefault();
    const val = keyInputVal.value.trim();
    const label = keyInputLabel.value.trim();
    if (!val || !label) return;

    const hash = await computeSHA256(val);
    const item = {
      id: 'key-' + Date.now(),
      chave: val,
      chave_hash: hash,
      rotulo: label,
      ativa: keyInputActive.checked,
      criada_em: new Date().toISOString(),
      ultimo_acesso: null,
      total_usos: 0
    };

    try {
      await Storage.saveKey(item);
      closeModal(modalKey);
      renderDashboard();
    } catch (err) {
      alert('Erro ao salvar chave: ' + err.message);
    }
  });

  // Modal: Conexão em Nuvem
  btnOpenCloud.addEventListener('click', () => {
    const cfg = Storage.getCloudConfig();
    cloudUrl.value = cfg ? cfg.url : '';
    cloudKey.value = cfg ? cfg.key : '';
    cloudFeedback.className = 'feedback-msg hidden';
    openModal(modalCloud);
  });

  btnTestCloud.addEventListener('click', async () => {
    const u = cloudUrl.value.trim();
    const k = cloudKey.value.trim();
    cloudFeedback.className = 'feedback-msg';
    cloudFeedback.textContent = 'Testando conexão com Supabase...';
    try {
      const res = await fetch(`${u}/rest/v1/chaves_acesso?limit=1`, {
        headers: { 'apikey': k, 'Authorization': `Bearer ${k}` }
      });
      if (res.ok) {
        cloudFeedback.className = 'feedback-msg success';
        cloudFeedback.textContent = '✅ Conexão estabelecida com sucesso! Tabelas encontradas.';
      } else {
        cloudFeedback.className = 'feedback-msg error';
        cloudFeedback.textContent = `❌ Erro (${res.status}): Verifique se executou o script supabase_setup.sql no banco.`;
      }
    } catch (e) {
      cloudFeedback.className = 'feedback-msg error';
      cloudFeedback.textContent = '❌ Falha de rede: ' + e.message;
    }
  });

  formCloud.addEventListener('submit', async (e) => {
    e.preventDefault();
    const u = cloudUrl.value.trim();
    const k = cloudKey.value.trim();
    if (u && k) {
      Storage.setCloudConfig({ url: u, key: k });
    } else {
      Storage.setCloudConfig(null);
    }
    closeModal(modalCloud);
    updateCloudStatusUI();
    renderDashboard();
  });

  btnDisconnectCloud.addEventListener('click', () => {
    Storage.setCloudConfig(null);
    closeModal(modalCloud);
    updateCloudStatusUI();
    renderDashboard();
  });

  // Modal: Senha ADM
  btnOpenAdminPass.addEventListener('click', () => {
    newAdminPass.value = '';
    confirmAdminPass.value = '';
    adminPassError.classList.remove('visible');
    openModal(modalAdminPass);
  });

  formAdminPass.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (newAdminPass.value !== confirmAdminPass.value) {
      adminPassError.classList.add('visible');
      return;
    }
    const h = await computeSHA256(newAdminPass.value);
    Storage.setAdminHash(h);
    closeModal(modalAdminPass);
    alert('Senha de administrador atualizada com sucesso!');
  });

  /* ==========================================================================
     STARTUP
     ========================================================================== */
  window.addEventListener('DOMContentLoaded', () => {
    if (sessionStorage.getItem('subinova_admin_logged') === '1') {
      showDashboard();
    } else {
      adminPassInput.focus();
    }
  });

})();
