(function () {
  'use strict';

  const LOCAL_STORAGE_KEYS = 'subinova_chaves_acesso';
  const LOCAL_STORAGE_CLOUD = 'subinova_cloud_config';
  const LOCAL_STORAGE_LOGS = 'subinova_logs_acesso';
  const SESSION_ADMIN_TOKEN = 'subinova_admin_token';

  const INITIAL_KEYS = [];

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
        h = g; f = e; e = (d + t1) >>> 0;
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
     CAMADA DE DADOS & NUVEM BLINDADA (SUPABASE RPC)
     ========================================================================== */
  const Storage = {
    getAdminToken() {
      return sessionStorage.getItem(SESSION_ADMIN_TOKEN) || '';
    },

    setAdminToken(token) {
      if (!token) sessionStorage.removeItem(SESSION_ADMIN_TOKEN);
      else sessionStorage.setItem(SESSION_ADMIN_TOKEN, token);
    },

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

    setCloudConfig(cfg) {
      if (!cfg) localStorage.removeItem(LOCAL_STORAGE_CLOUD);
      else localStorage.setItem(LOCAL_STORAGE_CLOUD, JSON.stringify(cfg));
    },

    isCloudEnabled() {
      const cfg = this.getCloudConfig();
      return !!(cfg && cfg.url && cfg.key);
    },

    async callRpc(fnName, payload) {
      const cfg = this.getCloudConfig();
      const res = await fetch(`${cfg.url}/rest/v1/rpc/${fnName}`, {
        method: 'POST',
        headers: {
          'apikey': cfg.key,
          'Authorization': `Bearer ${cfg.key}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload || {})
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.message || errData.details || `Erro HTTP ${res.status}`);
      }
      return await res.json();
    },

    async verifyAdminLogin(hash) {
      if (this.isCloudEnabled()) {
        try {
          const data = await this.callRpc('admin_login', { p_admin_hash: hash });
          return Boolean(data && data.ok);
        } catch (e) {
          console.error('Erro ao autenticar no Supabase:', e);
          return false;
        }
      }
      const stored = localStorage.getItem('subinova_admin_hash');
      return Boolean(stored && stored === hash);
    },

    async fetchAdminBundle() {
      if (this.isCloudEnabled()) {
        try {
          const data = await this.callRpc('admin_listar_dados', {
            p_admin_hash: this.getAdminToken()
          });
          if (data && data.ok) {
            if (Array.isArray(data.ips_bloqueados)) {
              currentBlockedIpsCache = data.ips_bloqueados.map(b => b.ip);
            }
            return data;
          }
          if (data && data.error === 'Acesso negado.') {
            logout();
          }
        } catch (e) {
          console.warn('Erro ao buscar dados da nuvem:', e);
        }
      }

      const raw = localStorage.getItem(LOCAL_STORAGE_KEYS);
      let chaves = INITIAL_KEYS;
      if (raw) {
        try { chaves = JSON.parse(raw); } catch (e) {}
      }
      return {
        ok: true,
        chaves,
        modo_manutencao: localStorage.getItem('subinova_modo_manutencao') === 'true',
        banner_ativo: localStorage.getItem('subinova_banner_ativo') === 'true',
        banner_mensagem: localStorage.getItem('subinova_banner_msg') || ''
      };
    },

    async fetchKeys() {
      const bundle = await this.fetchAdminBundle();
      return bundle.chaves || [];
    },

    async saveKey(item) {
      if (this.isCloudEnabled()) {
        const res = await this.callRpc('admin_salvar_chave', {
          p_admin_hash: this.getAdminToken(),
          p_chave: item.chave,
          p_chave_hash: item.chave_hash,
          p_rotulo: item.rotulo,
          p_ativa: Boolean(item.ativa),
          p_expira_em: item.expira_em || null,
          p_limite_usos: item.limite_usos ? Number(item.limite_usos) : null,
          p_sessao_ilimitada: Boolean(item.sessao_ilimitada)
        });
        if (!res || !res.ok) {
          throw new Error((res && res.error) || 'Não foi possível salvar a chave.');
        }
        return;
      }

      const keys = await this.fetchKeys();
      const idx = keys.findIndex(k => k.id === item.id || k.chave === item.chave);
      if (idx >= 0) keys[idx] = { ...keys[idx], ...item };
      else keys.unshift(item);
      localStorage.setItem(LOCAL_STORAGE_KEYS, JSON.stringify(keys));
    },

    async banIp(ip, motivo) {
      if (this.isCloudEnabled()) {
        const res = await this.callRpc('admin_banir_ip', {
          p_admin_hash: this.getAdminToken(),
          p_ip: ip,
          p_motivo: motivo || 'Bloqueado pelo Administrador'
        });
        if (!res || !res.ok) throw new Error((res && res.error) || 'Erro ao banir IP.');
        return;
      }
    },

    async unbanIp(ip) {
      if (this.isCloudEnabled()) {
        const res = await this.callRpc('admin_desbanir_ip', {
          p_admin_hash: this.getAdminToken(),
          p_ip: ip
        });
        if (!res || !res.ok) throw new Error((res && res.error) || 'Erro ao desbanir IP.');
        return;
      }
    },

    async toggleKeyStatus(id, newStatus) {
      if (this.isCloudEnabled()) {
        const res = await this.callRpc('admin_alterar_status_chave', {
          p_admin_hash: this.getAdminToken(),
          p_id: id,
          p_ativa: Boolean(newStatus)
        });
        if (!res || !res.ok) throw new Error((res && res.error) || 'Erro ao alterar status na nuvem.');
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
        const res = await this.callRpc('admin_excluir_chave', {
          p_admin_hash: this.getAdminToken(),
          p_id: id
        });
        if (!res || !res.ok) throw new Error((res && res.error) || 'Erro ao excluir na nuvem.');
        return;
      }

      let keys = await this.fetchKeys();
      keys = keys.filter(k => k.id !== id);
      localStorage.setItem(LOCAL_STORAGE_KEYS, JSON.stringify(keys));
    },

    async getMaintenanceMode() {
      const bundle = await this.fetchAdminBundle();
      return Boolean(bundle.modo_manutencao);
    },

    async setMaintenanceMode(val) {
      if (this.isCloudEnabled()) {
        await this.callRpc('admin_salvar_configuracoes', {
          p_admin_hash: this.getAdminToken(),
          p_modo_manutencao: Boolean(val)
        });
      }
      localStorage.setItem('subinova_modo_manutencao', String(val));
    },

    async setAdminHash(newHash) {
      localStorage.setItem('subinova_admin_hash', newHash);
      if (this.isCloudEnabled()) {
        const res = await this.callRpc('admin_salvar_configuracoes', {
          p_admin_hash: this.getAdminToken(),
          p_novo_admin_hash: newHash
        });
        if (!res || !res.ok) {
          throw new Error((res && res.error) || 'Erro ao atualizar senha na nuvem.');
        }
      }
      this.setAdminToken(newHash);
    },

    async fetchLogs() {
      if (this.isCloudEnabled()) {
        try {
          const data = await this.callRpc('admin_listar_logs', {
            p_admin_hash: this.getAdminToken(),
            p_limite: 250
          });
          if (data && data.ok && Array.isArray(data.logs)) {
            return data.logs;
          }
        } catch (e) {
          console.warn('Erro ao buscar logs da nuvem:', e);
        }
      }

      try {
        const local = JSON.parse(localStorage.getItem(LOCAL_STORAGE_LOGS));
        if (Array.isArray(local)) return local;
      } catch (e) {}
      return [];
    },

    async getBannerConfig() {
      const bundle = await this.fetchAdminBundle();
      return {
        ativo: Boolean(bundle.banner_ativo),
        mensagem: bundle.banner_mensagem || ''
      };
    },

    async setBannerConfig(ativo, mensagem) {
      localStorage.setItem('subinova_banner_ativo', String(ativo));
      localStorage.setItem('subinova_banner_msg', mensagem);

      if (this.isCloudEnabled()) {
        const res = await this.callRpc('admin_salvar_configuracoes', {
          p_admin_hash: this.getAdminToken(),
          p_banner_ativo: Boolean(ativo),
          p_banner_mensagem: mensagem
        });
        if (!res || !res.ok) {
          throw new Error((res && res.error) || 'Erro ao salvar comunicado.');
        }
      }
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

  // Abas
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const tabLogsBadge = document.getElementById('tab-logs-badge');

  // Aba 1: Chaves
  const kpiTotal = document.getElementById('kpi-total-keys');
  const kpiActive = document.getElementById('kpi-active-keys');
  const kpiBlocked = document.getElementById('kpi-blocked-keys');
  const kpiMaintenance = document.getElementById('kpi-maintenance-status');
  const chkMaintenance = document.getElementById('chk-maintenance');

  const keysTableBody = document.getElementById('keys-table-body');
  const btnOpenNewKey = document.getElementById('btn-open-new-key');
  const btnOpenCloud = document.getElementById('btn-open-cloud-config');
  const btnOpenAdminPass = document.getElementById('btn-open-change-admin-pass');

  // Aba 2: Logs
  const logSearchInput = document.getElementById('log-search-input');
  const logFilterStatus = document.getElementById('log-filter-status');
  const btnExportCsv = document.getElementById('btn-export-csv');
  const btnRefreshLogs = document.getElementById('btn-refresh-logs');
  const logsTableBody = document.getElementById('logs-table-body');
  let currentLogsCache = [];
  let currentBlockedIpsCache = [];

  // Aba 3: Analytics
  const analyticsTotal = document.getElementById('analytics-total-count');
  const analyticsRate = document.getElementById('analytics-success-rate');
  const analyticsCities = document.getElementById('analytics-cities-count');
  const analyticsFailed = document.getElementById('analytics-failed-count');
  const chartDailyBars = document.getElementById('chart-daily-bars');
  const chartTopCities = document.getElementById('chart-top-cities');
  const chartDevicesList = document.getElementById('chart-devices-list');
  const chartTopKeys = document.getElementById('chart-top-keys');

  // Aba 4: Banner
  const chkBannerActive = document.getElementById('chk-banner-active');
  const bannerMessageInput = document.getElementById('banner-message-input');
  const bannerLivePreview = document.getElementById('banner-live-preview');
  const bannerPreviewText = document.getElementById('banner-preview-text');
  const formBanner = document.getElementById('form-banner');

  // Modais
  const modalKey = document.getElementById('modal-key');
  const formKey = document.getElementById('form-key');
  const keyInputVal = document.getElementById('key-input-val');
  const keyInputLabel = document.getElementById('key-input-label');
  const keyInputExpire = document.getElementById('key-input-expire');
  const keyInputMaxUses = document.getElementById('key-input-max-uses');
  const keyInputActive = document.getElementById('key-input-active');
  const keyInputUnlimitedSession = document.getElementById('key-input-unlimited-session');
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
     CONTROLE DE NAVEGAÇÃO POR ABAS
     ========================================================================== */
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');

      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.add('hidden'));

      btn.classList.add('active');
      const activePane = document.getElementById(targetTab);
      if (activePane) activePane.classList.remove('hidden');

      if (targetTab === 'tab-logs') {
        renderLogsView();
      } else if (targetTab === 'tab-analytics') {
        renderAnalyticsView();
      } else if (targetTab === 'tab-banner') {
        renderBannerView();
      } else {
        renderDashboard();
      }
    });
  });

  /* ==========================================================================
     AUTENTICAÇÃO DO ADMINISTRADOR
     ========================================================================== */
  async function checkAdminLogin() {
    const val = adminPassInput.value.trim();
    if (!val) return;

    const h = await computeSHA256(val);
    const isOk = await Storage.verifyAdminLogin(h);

    if (isOk) {
      Storage.setAdminToken(h);
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
    Storage.fetchLogs().then(logs => {
      currentLogsCache = logs;
      if (tabLogsBadge) tabLogsBadge.textContent = logs.length;
    });
  }

  function logout() {
    Storage.setAdminToken(null);
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
  });

  adminToggleEye.addEventListener('click', () => {
    const isPass = adminPassInput.type === 'password';
    adminPassInput.type = isPass ? 'text' : 'password';
  });

  btnAdminLogout.addEventListener('click', logout);

  /* ==========================================================================
     ABA 1: DASHBOARD & CHAVES
     ========================================================================== */
  function updateCloudStatusUI() {
    if (Storage.isCloudEnabled()) {
      syncBadge.classList.add('cloud-connected');
      syncText.textContent = 'Nuvem Conectada (RLS Blindado)';
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
    const bundle = await Storage.fetchAdminBundle();
    const keys = bundle.chaves || [];
    const isMaint = Boolean(bundle.modo_manutencao);

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

    keysTableBody.innerHTML = '';
    if (keys.length === 0) {
      keysTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:#64748b;">Nenhuma chave cadastrada. Clique em "Criar Nova Chave" para começar.</td></tr>`;
      return;
    }

    const now = new Date();

    keys.forEach((k) => {
      const tr = document.createElement('tr');
      const maskVal = '••••••••';
      const realVal = k.chave;

      let isExpired = false;
      let isLimitReached = false;
      let validityHtml = '<span style="color:#64748b; font-size:11.5px;">Vitalícia / Ilimitada</span>';

      if (k.expira_em) {
        const expDate = new Date(k.expira_em);
        if (expDate < now) {
          isExpired = true;
          validityHtml = `<span class="status-pill failed" style="font-size:10.5px;">Expirou ${expDate.toLocaleDateString('pt-BR')}</span>`;
        } else {
          validityHtml = `<span style="color:#cbd5e1; font-size:11.5px;">Até ${expDate.toLocaleDateString('pt-BR')} ${expDate.toLocaleTimeString('pt-BR', {hour:'2-digit', minute:'2-digit'})}</span>`;
        }
      }

      if (k.limite_usos && k.limite_usos > 0) {
        if ((k.total_usos || 0) >= k.limite_usos) {
          isLimitReached = true;
          validityHtml += `<br><span class="status-pill failed" style="font-size:10.5px; margin-top:2px;">Limite Atingido (${k.total_usos}/${k.limite_usos})</span>`;
        } else {
          validityHtml += `<br><span style="color:#94a3b8; font-size:11px;">${k.total_usos || 0} de ${k.limite_usos} usos</span>`;
        }
      }

      const effectiveActive = k.ativa && !isExpired && !isLimitReached;

      tr.innerHTML = `
        <td>
          <span class="key-code" data-id="${k.id}">
            <span class="key-text">${maskVal}</span>
            <button type="button" class="btn-icon-reveal" title="Ver / Ocultar Chave" data-val="${escapeHtml(realVal)}">
              👁
            </button>
          </span>
        </td>
        <td>
          <b class="key-label-text">${escapeHtml(k.rotulo || 'Sem identificador')}</b>
          ${k.sessao_ilimitada ? '<div style="font-size:11px; color:#10b981; font-weight:600; margin-top:2px;">👑 Sessão Contínua (Chefe)</div>' : '<div style="font-size:11px; color:#64748b; margin-top:2px;">⏱️ F5 a cada 5 min</div>'}
        </td>
        <td style="color:#94a3b8; font-size:12px;">${formatDate(k.criada_em)}</td>
        <td>${validityHtml}</td>
        <td style="color:#94a3b8; font-size:12px;">${formatDate(k.ultimo_acesso)}</td>
        <td><span style="font-weight:600; color:#38bdf8;">${k.total_usos || 0}</span></td>
        <td>
          <span class="status-pill ${effectiveActive ? 'active' : 'blocked'}">
            <span style="width:6px;height:6px;border-radius:50%;background:currentColor;"></span>
            ${effectiveActive ? 'Ativa' : (isExpired ? 'Expirada' : (isLimitReached ? 'Esgotada' : 'Bloqueada'))}
          </span>
        </td>
        <td>
          <div class="row-actions">
            <button type="button" class="btn-table-link" data-act="copy-link" data-key="${escapeHtml(realVal)}" title="Copiar Link de 1 Clique">
              🔗 1-Clique
            </button>
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

    document.querySelectorAll('[data-act="copy-link"]').forEach((btn) => {
      btn.onclick = async () => {
        const key = btn.getAttribute('data-key');
        const url = new URL(window.location.href);
        let basePath = url.pathname.substring(0, url.pathname.lastIndexOf('/') + 1);
        if (!basePath) basePath = '/';
        const accessUrl = `${url.origin}${basePath}index.html?k=${encodeURIComponent(key)}`;
        try {
          await navigator.clipboard.writeText(accessUrl);
          const orig = btn.innerHTML;
          btn.innerHTML = '✅ Copiado!';
          setTimeout(() => { btn.innerHTML = orig; }, 2000);
        } catch (e) {
          prompt('Copie o link de 1 clique abaixo:', accessUrl);
        }
      };
    });

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

  chkMaintenance.addEventListener('change', async () => {
    const isMaint = chkMaintenance.checked;
    await Storage.setMaintenanceMode(isMaint);
    renderDashboard();
  });

  /* ==========================================================================
     ABA 2: AUDITORIA DE LOGS & IPS
     ========================================================================== */
  async function renderLogsView() {
    logsTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:#64748b;">Carregando logs de auditoria...</td></tr>`;
    const logs = await Storage.fetchLogs();
    currentLogsCache = logs;
    if (tabLogsBadge) tabLogsBadge.textContent = logs.length;
    applyLogsFilter();
  }

  function applyLogsFilter() {
    const term = (logSearchInput.value || '').trim().toLowerCase();
    const statusFilter = logFilterStatus.value;

    let filtered = currentLogsCache.filter(item => {
      if (statusFilter === 'success' && !item.sucesso) return false;
      if (statusFilter === 'failed' && item.sucesso) return false;

      if (!term) return true;
      const haystack = [
        item.ip,
        item.cidade,
        item.regiao,
        item.pais,
        item.chave,
        item.rotulo,
        item.provedor,
        item.dispositivo,
        item.navegador,
        item.detalhes
      ].join(' ').toLowerCase();

      return haystack.includes(term);
    });

    logsTableBody.innerHTML = '';
    if (filtered.length === 0) {
      logsTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:#64748b;">Nenhum log encontrado para os critérios selecionados.</td></tr>`;
      return;
    }

    filtered.forEach(log => {
      const tr = document.createElement('tr');
      const isOk = Boolean(log.sucesso);

      let statusBadge;
      if (isOk) {
        statusBadge = `<span class="status-pill success">Liberado</span>`;
      } else if (log.detalhes && /bloqueada|expirada|limite/i.test(log.detalhes)) {
        statusBadge = `<span class="status-pill warn">Bloqueado</span>`;
      } else {
        statusBadge = `<span class="status-pill failed">Negado</span>`;
      }

      const cityDisplay = log.cidade && log.cidade !== 'N/A'
        ? `${log.cidade}${log.regiao ? ', ' + log.regiao : ''}`
        : (log.pais || 'Brasil');

      const logIp = log.ip || '0.0.0.0';
      const isBanned = currentBlockedIpsCache.includes(logIp);
      const canBan = logIp && logIp !== '0.0.0.0' && logIp !== '127.0.0.1';

      tr.innerHTML = `
        <td style="color:#94a3b8; font-size:12px; white-space:nowrap;">${formatDate(log.criado_em)}</td>
        <td>
          <b style="color:#38bdf8; font-family:monospace; font-size:13px;">${escapeHtml(log.chave || 'N/A')}</b>
          ${log.rotulo && log.rotulo !== 'N/A' ? `<div style="font-size:11px; color:#64748b;">${escapeHtml(log.rotulo)}</div>` : ''}
        </td>
        <td>${statusBadge}</td>
        <td>
          <div style="display:inline-flex; align-items:center;">
            <span class="ip-badge" style="${isBanned ? 'background:rgba(239,68,68,0.2); color:#ef4444; border-color:#ef4444;' : ''}">${escapeHtml(logIp)}</span>
            ${canBan ? `
              <button type="button" class="btn-ban-ip ${isBanned ? 'is-banned' : ''}" data-act="ban-ip" data-ip="${escapeHtml(logIp)}" data-banned="${isBanned}" title="${isBanned ? 'Desbanir IP' : 'Bloquear IP'}">
                ${isBanned ? 'Desbanir' : 'Banir'}
              </button>
            ` : ''}
          </div>
        </td>
        <td>
          <span class="location-text">
            <span>📍</span>
            <span>${escapeHtml(cityDisplay)}</span>
          </span>
        </td>
        <td><span class="provider-text" title="${escapeHtml(log.provedor || 'Desconhecido')}">${escapeHtml(log.provedor || 'N/A')}</span></td>
        <td>
          <span class="device-badge">
            <b>${escapeHtml(log.dispositivo || 'PC')}</b> · ${escapeHtml(log.navegador || 'Browser')}
          </span>
        </td>
        <td style="color:#94a3b8; font-size:11.5px; max-width:200px;">${escapeHtml(log.detalhes || '')}</td>
      `;

      logsTableBody.appendChild(tr);
    });

    logsTableBody.querySelectorAll('[data-act="ban-ip"]').forEach((btn) => {
      btn.onclick = async () => {
        const ip = btn.getAttribute('data-ip');
        const isBanned = btn.getAttribute('data-banned') === 'true';
        if (isBanned) {
          if (confirm(`Deseja desbloquear o acesso para o IP ${ip}?`)) {
            try {
              await Storage.unbanIp(ip);
              currentBlockedIpsCache = currentBlockedIpsCache.filter(item => item !== ip);
              applyLogsFilter();
            } catch (e) {
              alert('Erro ao desbanir IP: ' + e.message);
            }
          }
        } else {
          const motivo = prompt(`Digite o motivo do banimento para o IP ${ip}:`, 'Tentativas suspeitas / Violação de segurança');
          if (motivo !== null) {
            try {
              await Storage.banIp(ip, motivo);
              if (!currentBlockedIpsCache.includes(ip)) currentBlockedIpsCache.push(ip);
              applyLogsFilter();
            } catch (e) {
              alert('Erro ao banir IP: ' + e.message);
            }
          }
        }
      };
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  logSearchInput.addEventListener('input', applyLogsFilter);
  logFilterStatus.addEventListener('change', applyLogsFilter);
  btnRefreshLogs.addEventListener('click', renderLogsView);

  function exportLogsCSV() {
    if (!currentLogsCache || currentLogsCache.length === 0) {
      alert('Não há registros para exportar.');
      return;
    }

    const headers = [
      'Data e Hora (Brasília)',
      'Chave Digitada',
      'Identificador / Rótulo',
      'Status de Acesso',
      'Endereço IP',
      'Cidade',
      'Estado / Região',
      'País',
      'Provedor de Internet (ISP)',
      'Sistema Operacional',
      'Navegador',
      'Detalhes / Motivo'
    ];

    const rows = currentLogsCache.map(l => [
      formatDate(l.criado_em),
      l.chave || '',
      l.rotulo || '',
      l.sucesso ? 'Acesso Liberado' : 'Acesso Negado',
      l.ip || '',
      l.cidade || '',
      l.regiao || '',
      l.pais || 'Brasil',
      l.provedor || '',
      l.dispositivo || '',
      l.navegador || '',
      l.detalhes || ''
    ]);

    const csvContent = '\uFEFF' + [
      headers.map(h => `"${h.replace(/"/g, '""')}"`).join(';'),
      ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(';'))
    ].join('\r\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `auditoria_acessos_subinova_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  btnExportCsv.addEventListener('click', exportLogsCSV);

  /* ==========================================================================
     ABA 3: ESTATÍSTICAS & ANALYTICS
     ========================================================================== */
  async function renderAnalyticsView() {
    const logs = await Storage.fetchLogs();
    currentLogsCache = logs;

    const total = logs.length;
    const successes = logs.filter(l => l.sucesso).length;
    const failed = total - successes;
    const rate = total > 0 ? Math.round((successes / total) * 100) : 100;

    const citiesSet = new Set();
    logs.forEach(l => {
      if (l.cidade && l.cidade !== 'N/A' && l.cidade !== 'Desconhecido') {
        citiesSet.add(l.cidade);
      }
    });

    analyticsTotal.textContent = total;
    analyticsRate.textContent = `${rate}%`;
    analyticsCities.textContent = citiesSet.size;
    analyticsFailed.textContent = failed;

    renderDailyBarsChart(logs);
    renderTopRanking(chartTopCities, logs, l => (l.cidade && l.cidade !== 'N/A' ? `${l.cidade} (${l.regiao || 'BR'})` : null));
    renderTopRanking(chartDevicesList, logs, l => (l.dispositivo ? `${l.dispositivo} · ${l.navegador || 'Web'}` : null));
    renderTopRanking(chartTopKeys, logs, l => (l.chave ? `${l.chave}${l.rotulo ? ' (' + l.rotulo + ')' : ''}` : null));
  }

  function renderDailyBarsChart(logs) {
    chartDailyBars.innerHTML = '';
    const days = [];
    const now = new Date();

    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const dayStr = d.toISOString().slice(0, 10);
      const label = i === 0 ? 'Hoje' : (i === 1 ? 'Ontem' : d.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' }));
      days.push({ dayStr, label, count: 0 });
    }

    logs.forEach(l => {
      if (!l.criado_em) return;
      const lDay = l.criado_em.slice(0, 10);
      const match = days.find(d => d.dayStr === lDay);
      if (match) match.count++;
    });

    const maxCount = Math.max(...days.map(d => d.count), 1);

    days.forEach(d => {
      const col = document.createElement('div');
      col.className = 'bar-col';

      const heightPercent = Math.max(Math.round((d.count / maxCount) * 100), 5);

      col.innerHTML = `
        <span class="bar-value">${d.count}</span>
        <div class="bar-track">
          <div class="bar-fill" style="height: ${heightPercent}%;"></div>
        </div>
        <span class="bar-label">${d.label}</span>
      `;

      chartDailyBars.appendChild(col);
    });
  }

  function renderTopRanking(container, logs, extractor) {
    container.innerHTML = '';
    const counts = {};

    logs.forEach(l => {
      const key = extractor(l);
      if (!key) return;
      counts[key] = (counts[key] || 0) + 1;
    });

    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);

    if (sorted.length === 0) {
      container.innerHTML = `<span style="color:#64748b; font-size:12px;">Sem dados suficientes registrados.</span>`;
      return;
    }

    const max = sorted[0][1];

    sorted.forEach(([title, count], index) => {
      const item = document.createElement('div');
      item.className = 'ranking-item';
      const pct = Math.max(Math.round((count / max) * 100), 10);

      item.innerHTML = `
        <div class="ranking-info">
          <span class="ranking-title">
            <span class="ranking-rank ${index === 0 ? 'top1' : ''}">${index + 1}</span>
            <span>${escapeHtml(title)}</span>
          </span>
          <span class="ranking-count">${count} acessos</span>
        </div>
        <div class="ranking-bar-track">
          <div class="ranking-bar-fill" style="width: ${pct}%;"></div>
        </div>
      `;

      container.appendChild(item);
    });
  }

  /* ==========================================================================
     ABA 4: BANNER DE AVISOS / COMUNICADOS
     ========================================================================== */
  async function renderBannerView() {
    const cfg = await Storage.getBannerConfig();
    chkBannerActive.checked = cfg.ativo;
    bannerMessageInput.value = cfg.mensagem;
    updateBannerPreview();
  }

  function updateBannerPreview() {
    const text = bannerMessageInput.value.trim();
    if (!text) {
      bannerPreviewText.textContent = 'Nenhum comunicado ativo no momento.';
      bannerLivePreview.style.opacity = '0.5';
    } else {
      bannerPreviewText.textContent = text;
      bannerLivePreview.style.opacity = '1';
    }
  }

  bannerMessageInput.addEventListener('input', updateBannerPreview);

  formBanner.addEventListener('submit', async (e) => {
    e.preventDefault();
    const ativo = chkBannerActive.checked;
    const msg = bannerMessageInput.value.trim();

    const saveBtn = document.getElementById('btn-save-banner');
    saveBtn.disabled = true;
    saveBtn.textContent = 'Salvando...';

    try {
      await Storage.setBannerConfig(ativo, msg);
      saveBtn.innerHTML = `<span>✅ Comunicado Salvo!</span>`;
      setTimeout(() => {
        saveBtn.disabled = false;
        saveBtn.innerHTML = `
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
            <polyline points="17 21 17 13 7 13 7 21"/>
            <polyline points="7 3 7 8 15 8"/>
          </svg>
          <span>Salvar Comunicado</span>
        `;
      }, 1800);
    } catch (err) {
      alert('Erro ao salvar comunicado: ' + err.message);
      saveBtn.disabled = false;
    }
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

  btnOpenNewKey.addEventListener('click', () => {
    keyInputVal.value = '';
    keyInputLabel.value = '';
    keyInputExpire.value = '';
    keyInputMaxUses.value = '';
    keyInputActive.checked = true;
    if (keyInputUnlimitedSession) keyInputUnlimitedSession.checked = false;
    openModal(modalKey);
    keyInputVal.focus();
  });

  btnGenerateKey.addEventListener('click', () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    const bytes = new Uint8Array(8);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < 8; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    let token = '';
    for (let i = 0; i < 8; i++) {
      token += chars[bytes[i] % chars.length];
    }
    const prefixes = ['@subinova', '@sede', '@acesso', '@minas', '@inova'];
    const p = prefixes[bytes[0] % prefixes.length];
    keyInputVal.value = `${p}-${token}`;
  });

  formKey.addEventListener('submit', async (e) => {
    e.preventDefault();
    const val = keyInputVal.value.trim();
    const label = keyInputLabel.value.trim();
    if (!val || !label) return;

    const hash = await computeSHA256(val);
    let newId;
    try {
      newId = crypto.randomUUID();
    } catch (e) {
      newId = 'key-' + Date.now();
    }

    const expireVal = keyInputExpire.value ? new Date(keyInputExpire.value).toISOString() : null;
    const maxUsesVal = keyInputMaxUses.value ? parseInt(keyInputMaxUses.value, 10) : null;

    const item = {
      id: newId,
      chave: val,
      chave_hash: hash,
      rotulo: label,
      ativa: keyInputActive.checked,
      expira_em: expireVal,
      limite_usos: maxUsesVal,
      sessao_ilimitada: keyInputUnlimitedSession ? keyInputUnlimitedSession.checked : false,
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
    cloudFeedback.textContent = 'Testando conexão segura RPC com Supabase...';
    try {
      const res = await fetch(`${u}/rest/v1/rpc/obter_status_portal`, {
        method: 'POST',
        headers: {
          'apikey': k,
          'Authorization': `Bearer ${k}`,
          'Content-Type': 'application/json'
        },
        body: '{}'
      });
      if (res.ok) {
        cloudFeedback.className = 'feedback-msg success';
        cloudFeedback.textContent = '✅ Conexão blindada estabelecida com sucesso!';
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

  btnOpenAdminPass.addEventListener('click', () => {
    newAdminPass.value = '';
    confirmAdminPass.value = '';
    adminPassError.classList.remove('visible');
    openModal(modalAdminPass);
  });

  formAdminPass.addEventListener('submit', async (e) => {
    e.preventDefault();
    const p1 = newAdminPass.value.trim();
    const p2 = confirmAdminPass.value.trim();
    if (!p1 || p1 !== p2) {
      adminPassError.classList.add('visible');
      return;
    }
    try {
      const h = await computeSHA256(p1);
      await Storage.setAdminHash(h);
      closeModal(modalAdminPass);
      alert('Senha de administrador atualizada com sucesso na nuvem!');
    } catch (err) {
      alert('Erro ao atualizar senha: ' + err.message);
    }
  });

  /* ==========================================================================
     STARTUP
     ========================================================================== */
  window.addEventListener('DOMContentLoaded', () => {
    if (Storage.getAdminToken()) {
      showDashboard();
    } else {
      adminPassInput.focus();
    }
  });

})();
