# MeuSacoTools — Backend (Railway + GitHub)

## Estrutura do repositório

Coloque estes 4 arquivos na raiz do repositório:

```
index.html      ← o site (use a versão corrigida que veio junto)
server.js       ← o servidor
package.json    ← dependências
.gitignore
```

**Importante:** o arquivo do site deve se chamar exatamente `index.html` (o original estava como `index.html.html`).

## 1. Subir para o GitHub

```bash
git init
git add .
git commit -m "MeuSacoTools"
git branch -M main
git remote add origin https://github.com/SEU_USUARIO/meusacotools.git
git push -u origin main
```

## 2. Deploy no Railway

1. No seu projeto do Railway (o mesmo que já tem o PostgreSQL), clique em **+ New → GitHub Repo** e escolha o repositório.
2. No serviço criado, vá em **Variables** e adicione:

| Variável | Valor |
|---|---|
| `DATABASE_URL` | **Add Reference** → selecione o Postgres do projeto |
| `TZ` | `America/Sao_Paulo` |
| `META_APP_ID` | ID do seu app na Meta (para conectar contas Instagram) |
| `META_APP_SECRET` | Secret do app da Meta |
| `APP_URL` | URL pública do serviço, ex: `https://meusacotools.up.railway.app` |

3. Em **Settings → Networking**, clique em **Generate Domain** (use essa URL no `APP_URL`).
4. O deploy roda `npm start` automaticamente. As tabelas do banco são criadas sozinhas no primeiro boot — não precisa rodar SQL manual.

## 3. Primeiro acesso

- **O primeiro usuário que criar conta vira admin automaticamente.**
- Logado como admin, vá em **Configurações** e preencha o storage de vídeos (Backblaze B2 ou Cloudflare R2, via API S3):
  - Key ID, App Key, Bucket, Endpoint S3 (ex: `https://s3.us-west-004.backblazeb2.com`) e a **URL pública** do bucket (o Instagram precisa baixar o vídeo por essa URL, então o bucket deve ser público).

## 4. App da Meta (conectar contas Instagram)

O botão "Adicionar conta" usa OAuth da Meta. No [developers.facebook.com](https://developers.facebook.com):

1. Crie um app do tipo **Business** e adicione o produto **Facebook Login**.
2. Em Facebook Login → Configurações, adicione a **Valid OAuth Redirect URI**:
   `https://SEU_DOMINIO/api/auth/facebook/callback`
3. Permissões usadas: `instagram_basic`, `instagram_content_publish`, `pages_show_list`, `pages_read_engagement`, `business_management`.
4. A conta do Instagram precisa ser **Business ou Creator** e estar **vinculada a uma Página do Facebook** — é assim que a API oficial de publicação funciona.
5. Em modo de desenvolvimento do app, só contas com papel no app (admin/tester) conseguem conectar. Para uso geral, é preciso passar pelo App Review da Meta.

## Como funciona a publicação

- O upload dos vídeos vai direto do navegador para o bucket (URL presignada) — não passa pelo servidor.
- O servidor agenda os posts dentro da janela configurada na conta (horário início/fim × posts por dia).
- Um worker interno roda a cada 30 segundos, pega os vídeos vencidos e publica como **Reels** via Graph API, com barra de progresso na tela de Vídeos.

## Correções feitas no index.html

Além do servidor, corrigi 2 bugs no seu front que quebravam depois do upload:

1. Variável `done` inexistente no final de `runUploadPresign` (causava erro e travava a atualização da fila) — bloco duplicado removido.
2. `showToast(...)` → `toast(...)` na função `addAccount` (a função `showToast` não existe).
