# build-pipeline-probe

Probe de reconhecimento (somente leitura) pra testar isolamento de build/sandbox
no engagement **Railway Managed Bug Bounty** (Bugcrowd).

## O que faz

Roda `recon.js` em dois momentos:

- **Build time** (`postinstall`, durante `npm install`) — checa o ambiente do
  builder (Nixpacks/buildkit).
- **Runtime** (`start`, no container final) — checa o ambiente do container
  que efetivamente serve o serviço.

Em cada fase, coleta e loga (stdout + `recon-output.json`, servido em
`/recon.json`):

1. Identidade (hostname, uid/gid, arch, SO)
2. Todas as env vars — o ponto principal: ver se algo de **outro tenant**
   vaza pro nosso ambiente (segredo, token, hostname interno)
3. Fingerprint de container: `/proc/self/cgroup`, `/proc/version`,
   `/proc/self/mountinfo`, presença de `.dockerenv` / `docker.sock`
4. Token de service account do Kubernetes (se existir — indicador comum de
   orquestrador compartilhado)
5. Listagem de `/`, `/tmp`, home — procurando artefato de outro build/tenant
6. Interfaces de rede locais (sem scan)
7. Resolução DNS de hostnames internos comuns (`kubernetes.default`, etc.)
8. Uma única requisição HTTP, com timeout curto, pros endpoints de metadata
   de nuvem mais conhecidos (AWS/GCP/Azure/Alibaba) — checagem clássica de
   SSRF/isolamento, não é scan de rede

## O que NÃO faz

- Não deleta, sobrescreve ou modifica nada.
- Não faz scan de porta nem varredura de IP.
- Não manda dado pra lugar nenhum fora do próprio log/HTTP do serviço.
- Não tenta acessar recurso de outro tenant além de observar o que já
  aparece espontaneamente no próprio ambiente.

## Como usar

1. Suba isso como repo no GitHub (ou "Empty Service" + colar os arquivos).
2. Deploy no Railway, na sua própria conta/projeto de teste.
3. Depois do deploy: olha o **Build Logs** (pega a fase `build`) e o
   **Deploy Logs** (fase `runtime`), ou abre a URL pública do serviço e
   visita `/recon.json`.
4. Se qualquer coisa aparecer que não é sua (env var de outro projeto,
   hostname/IP que não bate com o seu, resposta de metadata endpoint com
   credencial de verdade) — **para e reporta na Bugcrowd**, não segue
   investigando. É a regra do programa pra achados de pós-exploração.
