-- ============================================================================
-- BANCO DE DADOS EM NUVEM BLINDADO (SUPABASE / POSTGRESQL)
-- Portal de Resultados SUBINOVA · Arquitetura RPC + RLS Restrito
-- ============================================================================

-- 1. Tabela de Chaves de Acesso
CREATE TABLE IF NOT EXISTS public.chaves_acesso (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    chave TEXT NOT NULL UNIQUE,
    chave_hash TEXT NOT NULL,
    rotulo TEXT NOT NULL,
    ativa BOOLEAN NOT NULL DEFAULT true,
    expira_em TIMESTAMPTZ,
    limite_usos INTEGER,
    criada_em TIMESTAMPTZ DEFAULT NOW(),
    ultimo_acesso TIMESTAMPTZ,
    total_usos INTEGER DEFAULT 0
);

ALTER TABLE public.chaves_acesso ADD COLUMN IF NOT EXISTS expira_em TIMESTAMPTZ;
ALTER TABLE public.chaves_acesso ADD COLUMN IF NOT EXISTS limite_usos INTEGER;

-- 2. Tabela de Configurações Gerais
CREATE TABLE IF NOT EXISTS public.configuracoes (
    chave TEXT PRIMARY KEY,
    valor TEXT NOT NULL
);

INSERT INTO public.configuracoes (chave, valor)
VALUES 
    ('modo_manutencao', 'false'),
    ('mensagem_manutencao', 'Painel temporariamente indisponível para atualização.'),
    ('banner_ativo', 'false'),
    ('banner_mensagem', 'Bem-vindo ao Portal de Resultados SUBINOVA.'),
    ('pbi_url', 'https://app.powerbi.com/view?r=eyJrIjoiNTgwNTFlOTctODk2OC00ZjFmLWIwZDUtMjg4ZmFhMDgyOGNkIiwidCI6ImU1ZDNhZTdjLTliMzgtNDhkZS1hMDg3LWY2NzM0YTI4NzU3NCJ9')
ON CONFLICT (chave) DO NOTHING;

-- 3. Tabela de Logs de Acesso e Auditoria (IP, Geolocalização, Dispositivo)
CREATE TABLE IF NOT EXISTS public.logs_acesso (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    chave TEXT,
    rotulo TEXT,
    sucesso BOOLEAN NOT NULL DEFAULT true,
    ip TEXT,
    cidade TEXT,
    regiao TEXT,
    pais TEXT,
    provedor TEXT,
    dispositivo TEXT,
    navegador TEXT,
    detalhes TEXT,
    criado_em TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Políticas de Segurança Restritas (Row Level Security - RLS Blindado)
-- Bloqueia acesso direto via REST às tabelas; toda leitura/escrita ocorre via RPC SECURITY DEFINER
ALTER TABLE public.chaves_acesso ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.configuracoes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.logs_acesso ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Acesso total a chaves" ON public.chaves_acesso;
DROP POLICY IF EXISTS "Acesso público a configurações" ON public.configuracoes;
DROP POLICY IF EXISTS "Acesso total a logs" ON public.logs_acesso;
DROP POLICY IF EXISTS "Bloqueio direto chaves" ON public.chaves_acesso;
DROP POLICY IF EXISTS "Bloqueio direto configuracoes" ON public.configuracoes;
DROP POLICY IF EXISTS "Bloqueio direto logs" ON public.logs_acesso;

CREATE POLICY "Bloqueio direto chaves" ON public.chaves_acesso FOR ALL USING (false) WITH CHECK (false);
CREATE POLICY "Bloqueio direto configuracoes" ON public.configuracoes FOR ALL USING (false) WITH CHECK (false);
CREATE POLICY "Bloqueio direto logs" ON public.logs_acesso FOR ALL USING (false) WITH CHECK (false);

-- 5. Funções RPC Blindadas (SECURITY DEFINER)
CREATE OR REPLACE FUNCTION public.verificar_admin(p_admin_hash text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_stored text;
BEGIN
    IF p_admin_hash IS NULL OR length(trim(p_admin_hash)) = 0 THEN
        RETURN false;
    END IF;
    SELECT valor INTO v_stored FROM public.configuracoes WHERE chave = 'admin_hash';
    RETURN (v_stored IS NOT NULL AND v_stored = trim(p_admin_hash));
END;
$$;

CREATE OR REPLACE FUNCTION public.obter_status_portal()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_manut boolean := false;
    v_manut_msg text := 'Painel temporariamente indisponível para atualização.';
    v_banner boolean := false;
    v_banner_msg text := '';
    rec record;
BEGIN
    FOR rec IN SELECT chave, valor FROM public.configuracoes WHERE chave IN ('modo_manutencao', 'mensagem_manutencao', 'banner_ativo', 'banner_mensagem') LOOP
        IF rec.chave = 'modo_manutencao' THEN v_manut := (rec.valor = 'true'); END IF;
        IF rec.chave = 'mensagem_manutencao' THEN v_manut_msg := COALESCE(rec.valor, v_manut_msg); END IF;
        IF rec.chave = 'banner_ativo' THEN v_banner := (rec.valor = 'true'); END IF;
        IF rec.chave = 'banner_mensagem' THEN v_banner_msg := COALESCE(rec.valor, ''); END IF;
    END LOOP;

    RETURN jsonb_build_object(
        'modo_manutencao', v_manut,
        'mensagem_manutencao', v_manut_msg,
        'banner_ativo', v_banner,
        'banner_mensagem', v_banner_msg
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.validar_chave_acesso(
    p_chave text,
    p_hash text,
    p_ip text DEFAULT 'N/A',
    p_cidade text DEFAULT 'N/A',
    p_regiao text DEFAULT 'N/A',
    p_pais text DEFAULT 'Brasil',
    p_provedor text DEFAULT 'N/A',
    p_dispositivo text DEFAULT 'Desktop',
    p_navegador text DEFAULT 'Navegador',
    p_registrar_falha boolean DEFAULT true
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_manut text;
    v_pbi_url text;
    v_match public.chaves_acesso%ROWTYPE;
    v_clean text;
BEGIN
    v_clean := trim(COALESCE(p_chave, ''));
    IF length(v_clean) = 0 THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Digite uma senha.');
    END IF;

    SELECT valor INTO v_manut FROM public.configuracoes WHERE chave = 'modo_manutencao';
    IF v_manut = 'true' THEN
        IF p_registrar_falha THEN
            INSERT INTO public.logs_acesso (chave, rotulo, sucesso, ip, cidade, regiao, pais, provedor, dispositivo, navegador, detalhes)
            VALUES (v_clean, 'Tentativa', false, p_ip, p_cidade, p_regiao, p_pais, p_provedor, p_dispositivo, p_navegador, 'Bloqueado: Painel em Manutenção');
        END IF;
        RETURN jsonb_build_object('ok', false, 'error', 'Painel em manutenção temporária. Tente mais tarde.');
    END IF;

    SELECT * INTO v_match
    FROM public.chaves_acesso
    WHERE chave_hash = p_hash OR chave = v_clean
    LIMIT 1;

    IF NOT FOUND THEN
        IF p_registrar_falha THEN
            INSERT INTO public.logs_acesso (chave, rotulo, sucesso, ip, cidade, regiao, pais, provedor, dispositivo, navegador, detalhes)
            VALUES (v_clean, 'Tentativa Incorreta', false, p_ip, p_cidade, p_regiao, p_pais, p_provedor, p_dispositivo, p_navegador, 'Senha incorreta');
        END IF;
        RETURN jsonb_build_object('ok', false, 'error', 'Senha incorreta.');
    END IF;

    IF NOT v_match.ativa THEN
        IF p_registrar_falha THEN
            INSERT INTO public.logs_acesso (chave, rotulo, sucesso, ip, cidade, regiao, pais, provedor, dispositivo, navegador, detalhes)
            VALUES (v_match.chave, v_match.rotulo, false, p_ip, p_cidade, p_regiao, p_pais, p_provedor, p_dispositivo, p_navegador, 'Chave revogada/bloqueada');
        END IF;
        RETURN jsonb_build_object('ok', false, 'error', 'Esta chave de acesso foi desativada ou revogada pela administração.');
    END IF;

    IF v_match.expira_em IS NOT NULL AND NOW() > v_match.expira_em THEN
        IF p_registrar_falha THEN
            INSERT INTO public.logs_acesso (chave, rotulo, sucesso, ip, cidade, regiao, pais, provedor, dispositivo, navegador, detalhes)
            VALUES (v_match.chave, v_match.rotulo, false, p_ip, p_cidade, p_regiao, p_pais, p_provedor, p_dispositivo, p_navegador, 'Chave expirada por data');
        END IF;
        RETURN jsonb_build_object('ok', false, 'error', 'Esta chave de acesso expirou a data de validade.');
    END IF;

    IF v_match.limite_usos IS NOT NULL AND v_match.limite_usos > 0 AND COALESCE(v_match.total_usos, 0) >= v_match.limite_usos THEN
        IF p_registrar_falha THEN
            INSERT INTO public.logs_acesso (chave, rotulo, sucesso, ip, cidade, regiao, pais, provedor, dispositivo, navegador, detalhes)
            VALUES (v_match.chave, v_match.rotulo, false, p_ip, p_cidade, p_regiao, p_pais, p_provedor, p_dispositivo, p_navegador, 'Limite de usos atingido');
        END IF;
        RETURN jsonb_build_object('ok', false, 'error', 'Esta chave atingiu o limite máximo de utilizações permitidas.');
    END IF;

    UPDATE public.chaves_acesso
    SET total_usos = COALESCE(total_usos, 0) + 1,
        ultimo_acesso = NOW()
    WHERE id = v_match.id;

    INSERT INTO public.logs_acesso (chave, rotulo, sucesso, ip, cidade, regiao, pais, provedor, dispositivo, navegador, detalhes)
    VALUES (v_match.chave, v_match.rotulo, true, p_ip, p_cidade, p_regiao, p_pais, p_provedor, p_dispositivo, p_navegador, 'Acesso autenticado com sucesso');

    SELECT valor INTO v_pbi_url FROM public.configuracoes WHERE chave = 'pbi_url';

    RETURN jsonb_build_object(
        'ok', true,
        'rotulo', v_match.rotulo,
        'pbi_url', COALESCE(v_pbi_url, '')
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_login(p_admin_hash text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF public.verificar_admin(p_admin_hash) THEN
        RETURN jsonb_build_object('ok', true);
    ELSE
        RETURN jsonb_build_object('ok', false, 'error', 'Senha de administrador incorreta.');
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_listar_dados(p_admin_hash text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_chaves jsonb;
    v_manut boolean := false;
    v_banner boolean := false;
    v_banner_msg text := '';
    rec record;
BEGIN
    IF NOT public.verificar_admin(p_admin_hash) THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Acesso negado.');
    END IF;

    SELECT COALESCE(jsonb_agg(t), '[]'::jsonb) INTO v_chaves
    FROM (
        SELECT id, chave, chave_hash, rotulo, ativa, expira_em, limite_usos, criada_em, ultimo_acesso, total_usos
        FROM public.chaves_acesso
        ORDER BY criada_em DESC
    ) t;

    FOR rec IN SELECT chave, valor FROM public.configuracoes WHERE chave IN ('modo_manutencao', 'banner_ativo', 'banner_mensagem') LOOP
        IF rec.chave = 'modo_manutencao' THEN v_manut := (rec.valor = 'true'); END IF;
        IF rec.chave = 'banner_ativo' THEN v_banner := (rec.valor = 'true'); END IF;
        IF rec.chave = 'banner_mensagem' THEN v_banner_msg := COALESCE(rec.valor, ''); END IF;
    END LOOP;

    RETURN jsonb_build_object(
        'ok', true,
        'chaves', v_chaves,
        'modo_manutencao', v_manut,
        'banner_ativo', v_banner,
        'banner_mensagem', v_banner_msg
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_listar_logs(p_admin_hash text, p_limite integer DEFAULT 250)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_logs jsonb;
BEGIN
    IF NOT public.verificar_admin(p_admin_hash) THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Acesso negado.');
    END IF;

    SELECT COALESCE(jsonb_agg(t), '[]'::jsonb) INTO v_logs
    FROM (
        SELECT id, chave, rotulo, sucesso, ip, cidade, regiao, pais, provedor, dispositivo, navegador, detalhes, criado_em
        FROM public.logs_acesso
        ORDER BY criado_em DESC
        LIMIT COALESCE(p_limite, 250)
    ) t;

    RETURN jsonb_build_object('ok', true, 'logs', v_logs);
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_salvar_chave(
    p_admin_hash text,
    p_chave text,
    p_chave_hash text,
    p_rotulo text,
    p_ativa boolean DEFAULT true,
    p_expira_em timestamptz DEFAULT NULL,
    p_limite_usos integer DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF NOT public.verificar_admin(p_admin_hash) THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Acesso negado.');
    END IF;

    INSERT INTO public.chaves_acesso (chave, chave_hash, rotulo, ativa, expira_em, limite_usos)
    VALUES (trim(p_chave), p_chave_hash, trim(p_rotulo), COALESCE(p_ativa, true), p_expira_em, p_limite_usos)
    ON CONFLICT (chave) DO UPDATE
    SET chave_hash = EXCLUDED.chave_hash,
        rotulo = EXCLUDED.rotulo,
        ativa = EXCLUDED.ativa,
        expira_em = EXCLUDED.expira_em,
        limite_usos = EXCLUDED.limite_usos;

    RETURN jsonb_build_object('ok', true);
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_alterar_status_chave(
    p_admin_hash text,
    p_id text,
    p_ativa boolean
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF NOT public.verificar_admin(p_admin_hash) THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Acesso negado.');
    END IF;

    UPDATE public.chaves_acesso
    SET ativa = p_ativa
    WHERE id = p_id;

    RETURN jsonb_build_object('ok', true);
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_excluir_chave(
    p_admin_hash text,
    p_id text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF NOT public.verificar_admin(p_admin_hash) THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Acesso negado.');
    END IF;

    DELETE FROM public.chaves_acesso WHERE id = p_id;

    RETURN jsonb_build_object('ok', true);
END;
$$;

CREATE OR REPLACE FUNCTION public.admin_salvar_configuracoes(
    p_admin_hash text,
    p_modo_manutencao boolean DEFAULT NULL,
    p_banner_ativo boolean DEFAULT NULL,
    p_banner_mensagem text DEFAULT NULL,
    p_novo_admin_hash text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF NOT public.verificar_admin(p_admin_hash) THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Acesso negado.');
    END IF;

    IF p_modo_manutencao IS NOT NULL THEN
        INSERT INTO public.configuracoes (chave, valor)
        VALUES ('modo_manutencao', CASE WHEN p_modo_manutencao THEN 'true' ELSE 'false' END)
        ON CONFLICT (chave) DO UPDATE SET valor = EXCLUDED.valor;
    END IF;

    IF p_banner_ativo IS NOT NULL THEN
        INSERT INTO public.configuracoes (chave, valor)
        VALUES ('banner_ativo', CASE WHEN p_banner_ativo THEN 'true' ELSE 'false' END)
        ON CONFLICT (chave) DO UPDATE SET valor = EXCLUDED.valor;
    END IF;

    IF p_banner_mensagem IS NOT NULL THEN
        INSERT INTO public.configuracoes (chave, valor)
        VALUES ('banner_mensagem', p_banner_mensagem)
        ON CONFLICT (chave) DO UPDATE SET valor = EXCLUDED.valor;
    END IF;

    IF p_novo_admin_hash IS NOT NULL AND length(trim(p_novo_admin_hash)) > 0 THEN
        INSERT INTO public.configuracoes (chave, valor)
        VALUES ('admin_hash', trim(p_novo_admin_hash))
        ON CONFLICT (chave) DO UPDATE SET valor = EXCLUDED.valor;
    END IF;

    RETURN jsonb_build_object('ok', true);
END;
$$;
