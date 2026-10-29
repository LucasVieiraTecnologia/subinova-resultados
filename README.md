# Portal de Resultados e Indicadores · SUBINOVA

Portal institucional web moderno para visualização e consulta interativa dos resultados e indicadores da **SUBINOVA**.

---

## 🚀 Funcionalidades Principais

1. **Abertura Institucional com Vídeo de Load (~4 segundos)**:
   - Execução fluida do vídeo institucional de abertura (`videoResultados.mp4`).
   - Botão **"Pular Abertura ⏭"** e clique/toque na tela para acesso instantâneo sem espera.
   - Pré-carregamento invisível em segundo plano do painel do Power BI.

2. **Autenticação Criptografada (SHA-256)**:
   - Modal minimalista e responsivo que surge suavemente ao final do vídeo.
   - Desbloqueio instantâneo com validação criptográfica.
   - Suporte a múltiplas chaves de acesso ativas simultaneamente (ex: chave geral, diretoria, assessoria).

3. **Painel Administrativo Completo (`admin.html`)**:
   - Acesso seguro e restrito com Senha Master configurada pela administração.
   - Acesso rápido pelo atalho de teclado **`Ctrl + Shift + A`** ou pelo link discreto **"ADM"** no rodapé.
   - **Gestão de Chaves**:
     - Criação de novas chaves com identificador personalizado (ex: `@diretoria`, `@inova2026`).
     - Gerador de chaves aleatórias com 1 clique.
     - Máscara de segurança para ocultar/revelar chaves no painel.
     - **Bloqueio/Ativação imediata**: revogue ou reative o acesso de qualquer chave a qualquer momento.
     - Métricas de uso: contador de utilizações e data/hora do último acesso por chave.
   - **Modo Manutenção**:
     - Botão global liga/desliga para pausar temporariamente o acesso público ao portal.
   - **Alteração da Senha Master**.

4. **Sincronização em Nuvem em Tempo Real (Opcional - Supabase)**:
   - Funciona 100% offline via `localStorage` (padrão).
   - Suporte nativo à API REST do Supabase para propagação instantânea de chaves e bloqueios entre todos os usuários e dispositivos em escala global.
   - Script SQL pronto para provisionamento: [`portal/supabase_setup.sql`](portal/supabase_setup.sql).

---

## 🌐 Publicação no GitHub Pages

O portal foi construído em arquitetura estática cliente (HTML5, CSS3, JavaScript), **não requerendo servidores backend adicionais** para rodar na web.

### Como Publicar no GitHub Pages:
1. No seu repositório no GitHub, acesse a aba **Settings** (Configurações).
2. No menu lateral esquerdo, clique em **Pages**.
3. Em **Build and deployment** > **Branch**:
   - Selecione a branch `master` (ou `main`).
   - Selecione a pasta **`/docs`**.
4. Clique em **Save**.
5. Em poucos instantes, o GitHub fornecerá a URL pública:
   ```
   https://<seu-usuario>.github.io/<nome-do-repositorio>/
   ```

---

## 📁 Estrutura de Arquivos

```
├── docs/ / portal/
│   ├── index.html           # Tela de entrada com vídeo e modal de login
│   ├── styles.css           # Estilos visuais modernos (Dark Executive Theme)
│   ├── app.js               # Lógica de validação de chaves e transição do Power BI
│   ├── admin.html           # Dashboard do Administrador (KPIs, Tabela e Gestão)
│   ├── admin.css            # Estilos do painel administrativo
│   ├── admin.js             # Lógica do painel ADM, CRUD de chaves e sync nuvem
│   ├── supabase_setup.sql   # Script SQL para banco na nuvem Supabase
│   ├── videoResultados.mp4  # Vídeo institucional de abertura (~3.3 MB)
│   └── server.py            # Servidor local multi-threaded para desenvolvimento
├── powerbi/
│   ├── tema_subinova.json   # Paleta e tema visual corporativo
│   └── Medida_FiltrosAtivos.dax
├── Resumo Principal.dax     # Medida DAX otimizada dos cartões
└── README.md
```
