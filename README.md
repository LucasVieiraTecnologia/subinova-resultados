# Portal de Resultados e Indicadores · SUBINOVA

Portal institucional web moderno para visualização e consulta interativa dos resultados e indicadores da **SUBINOVA**.

---

## 🚀 Funcionalidades Principais

1. **Abertura Cinematográfica com Vídeo de Load (~4 segundos)**:
   - Execução automática em tela cheia do vídeo de abertura (`videoResultados.mp4`).
   - Pré-carregamento invisível em segundo plano do iframe do Power BI (zero tempo de espera ao autenticar).

2. **Autenticação Criptografada (SHA-256)**:
   - Modal minimalista e responsivo que surge suavemente ao final do vídeo.
   - Desbloqueio instantâneo ao digitar a chave de acesso correta.
   - Suporte a múltiplas chaves ativas simultaneamente (ex: chave geral, diretoria, assessoria).

3. **Painel Administrativo Completo (`admin.html`)**:
   - Acesso seguro com Senha Master (Padrão: `@admin3293`).
   - Acesso rápido pelo atalho de teclado **`Ctrl + Shift + A`** ou pelo link discreto no rodapé.
   - **Gestão de Chaves**:
     - Criar novas chaves com rótulo/identificador personalizado (ex: `@diretoria`, `@inova2026`).
     - Gerador aleatório de chaves com 1 clique.
     - Ocultar/revelar chaves no painel (máscara de segurança).
     - **Bloqueio/Ativação imediata**: revogue o acesso de qualquer chave a qualquer momento.
     - Contador de utilizações e data do último acesso por chave.
   - **Modo Manutenção**:
     - Botão global liga/desliga para pausar o acesso temporariamente ao portal.
   - **Alteração da Senha Master**.

4. **Sincronização em Nuvem em Tempo Real (Opcional - Supabase)**:
   - Funciona 100% offline via `localStorage` (padrão).
   - Conexão nativa com Supabase REST API (gratuito) para propagação instantânea de chaves e bloqueios entre todos os dispositivos e usuários do mundo sem precisar de servidor backend!
   - Script SQL pronto para execução em 1 clique: [`portal/supabase_setup.sql`](portal/supabase_setup.sql).

---

## 🌐 Publicação no GitHub Pages (Hospedagem Gratuita)

O portal foi construído em arquitetura estática cliente (HTML5, CSS3, JavaScript puro), o que significa que **não requer nenhum servidor backend ativo** para rodar na internet.

### Como Publicar no GitHub Pages:
1. No seu repositório no GitHub, acesse a aba **Settings** (Configurações).
2. No menu lateral esquerdo, clique em **Pages**.
3. Em **Build and deployment** > **Branch**:
   - Selecione a branch `master` (ou `main`).
   - Selecione a pasta `/ (root)` se os arquivos do portal estiverem na raiz, ou configure o workflow do GitHub Actions.
4. Clique em **Save**.
5. Em poucos instantes, o GitHub fornecerá a URL pública:
   ```
   https://<seu-usuario>.github.io/<nome-do-repositorio>/
   ```

---

## 🔐 Credenciais Padrão Iniciais

| Tipo | Chave Inicial | Onde Acessar |
| :--- | :--- | :--- |
| **Visitante** | `@3293` | Tela de entrada do portal (`index.html`) |
| **Administrador** | `@admin3293` | Painel ADM (`admin.html` ou `Ctrl+Shift+A`) |

---

## 📁 Estrutura de Arquivos

```
├── portal/
│   ├── index.html           # Tela de entrada com vídeo e modal de login
│   ├── styles.css           # Estilos visuais modernos (Dark Executive Theme)
│   ├── app.js               # Lógica de validação de chaves e transição do Power BI
│   ├── admin.html           # Dashboard do Administrador (KPIs, Tabela e Gestão)
│   ├── admin.css            # Estilos do painel administrativo
│   ├── admin.js             # Lógica do painel ADM, CRUD de chaves e sync nuvem
│   ├── supabase_setup.sql   # Script SQL para banco na nuvem Supabase
│   ├── videoResultados.mp4  # Vídeo institucional de abertura (~3.3 MB)
│   └── server.py            # Servidor local de testes em Python (opcional)
├── powerbi/
│   ├── tema_subinova.json   # Paleta e tema visual corporativo
│   └── Medida_FiltrosAtivos.dax
├── Resumo Principal.dax     # Medida DAX otimizada dos cartões
└── README.md
```
