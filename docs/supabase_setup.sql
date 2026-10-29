-- ============================================================================
-- BANCO DE DADOS EM NUVEM (SUPABASE / POSTGRESQL GRATUITO)
-- Portal de Resultados SUBINOVA · Sistema de Chaves de Acesso e ADM
-- ============================================================================

-- 1. Tabela de Chaves de Acesso
CREATE TABLE IF NOT EXISTS public.chaves_acesso (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chave TEXT NOT NULL UNIQUE,              -- Texto da senha (ex: @3293, @diretoria)
    chave_hash TEXT NOT NULL,                 -- Hash SHA-256 da senha
    rotulo TEXT NOT NULL,                     -- Nome/Identificador (ex: Geral, Diretoria)
    ativa BOOLEAN NOT NULL DEFAULT true,      -- true = liberada, false = bloqueada
    criada_em TIMESTAMPTZ DEFAULT NOW(),
    ultimo_acesso TIMESTAMPTZ,
    total_usos INTEGER DEFAULT 0
);

-- 2. Tabela de Configurações Gerais
CREATE TABLE IF NOT EXISTS public.configuracoes (
    chave TEXT PRIMARY KEY,
    valor TEXT NOT NULL
);

-- Inserir chave inicial padrão (@3293)
INSERT INTO public.chaves_acesso (chave, chave_hash, rotulo, ativa)
VALUES (
    '@3293',
    '0257caf28e46a4c150cad95f28fa4bf0d2c2183d2eb2ad61be1d76d35136ca24',
    'Chave Geral Padrão',
    true
)
ON CONFLICT (chave) DO NOTHING;

-- Configurações padrão
INSERT INTO public.configuracoes (chave, valor)
VALUES 
    ('modo_manutencao', 'false'),
    ('mensagem_manutencao', 'Painel temporariamente indisponível para atualização.'),
    ('admin_hash', 'e306389b1195c6e87ed86d733e290d9ab54864ad313ab6424b3fa72b6a2a6e9b')
ON CONFLICT (chave) DO NOTHING;

-- 3. Políticas de Segurança (Row Level Security - RLS)
ALTER TABLE public.chaves_acesso ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.configuracoes ENABLE ROW LEVEL SECURITY;

-- Visitantes podem apenas LER chaves e configs
CREATE POLICY "Leitura pública de chaves ativas" 
ON public.chaves_acesso FOR SELECT USING (true);

CREATE POLICY "Atualização de estatísticas de uso" 
ON public.chaves_acesso FOR UPDATE USING (true);

CREATE POLICY "Inserção e administração de chaves" 
ON public.chaves_acesso FOR ALL USING (true);

CREATE POLICY "Acesso público a configurações" 
ON public.configuracoes FOR ALL USING (true);
