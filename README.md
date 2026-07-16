# ◈ Doppel

**Encontra e remove ficheiros duplicados com segurança — verificação byte‑a‑byte,
login do sistema (PAM), quarentena reversível e um dashboard web em tempo real.**

Doppel é um binário Rust único, sem daemon e sem dependências de runtime. Corre‑lo na
linha de comandos, abre uma UI web moderna **embebida no próprio binário** numa porta
alta aleatória, e a partir do browser analisas uma pasta, decides o que fazer aos
duplicados e acompanhas o espaço a ser libertado ao vivo.

```bash
doppel                # analisa o teu home (por omissão)
doppel ~/Downloads    # ou uma pasta à tua escolha
```

```
  ✦ Doppel
  utilizador: walter
  raiz:       /home/walter/Downloads
  UI:         http://127.0.0.1:41879/
  (faz login com a tua password do sistema · Ctrl+C para sair)
```

O browser abre sozinho. Fazes login com a tua conta do sistema e começas.

---

## Porquê

Detetores de duplicados que apagam por *nome* ou só por *hash* podem enganar‑se — e um
apagar errado é irreversível. Doppel foi desenhado à volta de uma ideia: **nunca perder
um ficheiro que não seja, com 100% de certeza, uma cópia exata de outro que fica.**

- **Duas camadas de certeza.** Agrupa candidatos por **tamanho → hash BLAKE3** e, no
  instante *antes* de apagar/mover, faz uma **comparação byte‑a‑byte** com a cópia que
  fica. Se algo divergir (por exemplo, o ficheiro mudou entre a análise e a ação), é
  **ignorado, nunca apagado**.
- **Nunca apaga a última cópia** de um grupo. Em cada grupo mantém‑se sempre ≥1 ficheiro.
- **Quarentena reversível.** Em vez de apagar já, podes *mover* os duplicados para uma
  quarentena e decidir mais tarde — restaurar ou remover em definitivo.

---

## Funcionalidades

| | |
|---|---|
| 🔐 **Login PAM** | A UI é protegida pela tua password do sistema (PAM). Autenticas‑te a ti próprio sem root (via `unix_chkpwd`). Sessão por cookie `HttpOnly`. |
| 📁 **Escolha de pasta** | Começa no home do utilizador autenticado; navega e escolhe qualquer pasta a partir da UI. |
| 🧮 **Deteção exata** | Tamanho → BLAKE3 (hashing paralelo com todos os cores) → **byte‑a‑byte** na remoção. |
| 🛡 **Quarentena** | Move duplicados para `~/.local/share/doppel/quarantine` com manifesto persistente. Restaura ou purga quando quiseres. |
| 🗑 **Limpeza direta** | Ou apaga já, sempre com verificação byte‑a‑byte. |
| 📊 **Dashboard ao vivo** | Total na pasta, recuperável, em quarentena, já libertado, e **memória + disco** em tempo real. |
| ⏳ **Progresso animado** | Barra animada durante a análise (enumerar/hashing) e durante apagar/mover/purgar/restaurar. |
| 📦 **Binário único** | UI embebida, sem ficheiros externos. Porta alta aleatória atribuída pelo SO. |

---

## Instalação

### Binário pré‑compilado (Linux glibc)

Descarrega o binário para a tua arquitetura da
[página de Releases](https://github.com/angolardevops/doppel/releases):

```bash
# x86_64
curl -L -o doppel https://github.com/angolardevops/doppel/releases/latest/download/doppel-linux-x64
# ou aarch64 (ARM64)
curl -L -o doppel https://github.com/angolardevops/doppel/releases/latest/download/doppel-linux-arm64

chmod +x doppel
./doppel --help
```

> Doppel depende do PAM do sistema, que é específico do Linux e carrega os seus
> módulos dinamicamente — por isso os binários são **Linux (glibc)**; não há build
> estático (musl), macOS ou Windows. Cada release traz também um `.sha256`.

### A partir do código‑fonte

Precisas do toolchain Rust (`cargo`) e do libpam do sistema (presente em qualquer
distribuição Linux — não é preciso o pacote `-dev`, o build resolve o link sozinho).

```bash
cargo install --git https://github.com/angolardevops/doppel

# ou, a partir de um clone:
git clone https://github.com/angolardevops/doppel
cd doppel
cargo install --path .
```

---

## Como funciona

1. **`doppel [PASTA]`** — sobe o servidor web local e abre o browser.
2. **Login** com a tua conta do sistema.
3. **Escolhe a pasta** (por omissão, o teu home) e carrega em **Analisar**.
4. Vê os **grupos de duplicados**, ordenados por espaço desperdiçado. Em cada grupo, a
   cópia mais antiga fica marcada como **"manter"** (podes trocar).
5. Seleciona os extras e escolhe:
   - **🛡 Enviar p/ quarentena** — reversível, nada é apagado.
   - **🗑 Limpar (apagar já)** — liberta espaço de imediato.
6. No separador **Quarentena**, decides depois: **↩ Restaurar** ou **🔥 Remover definitivo**.

O espaço só é realmente libertado no disco quando apagas em definitivo (limpeza direta ou
purga da quarentena) — mover para quarentena é só um passo intermédio de segurança.

---

## Segurança e garantias

- **Verificação byte‑a‑byte** obrigatória antes de qualquer remoção ou movimento. O hash
  agrupa; a comparação de bytes é a palavra final.
- **Invariante:** nunca remove/quarentena o último membro de um grupo.
- **Sem lixo intermédio:** a limpeza direta apaga do disco (não vai para o Lixo) — daí a
  quarentena existir para quem quiser uma rede de segurança.
- **Local‑only:** o servidor liga apenas a `127.0.0.1` numa porta efémera; a sessão exige
  login PAM e o cookie é `HttpOnly; SameSite=Strict`.

> ⚠️ Doppel apaga ficheiros de forma permanente quando lhe pedes. Confirma sempre a
> seleção. A quarentena existe precisamente para poderes rever antes de libertar espaço.

---

## Configuração

| Variável | Por omissão | Descrição |
|---|---|---|
| `DOPPEL_PAM_SERVICE` | `login` | Serviço PAM usado na autenticação (ex.: `login`, `su`, `sudo`). |

Argumento posicional opcional: a pasta inicial a analisar (`doppel /caminho`).

---

## Detalhes técnicos

- **Rust**, sem `unsafe` fora do binding mínimo ao libpam.
- **Hashing paralelo** com [rayon](https://crates.io/crates/rayon) — só os ficheiros com
  colisão de tamanho são hasheados, por isso é rápido mesmo em dezenas de milhares de
  ficheiros.
- Servidor HTTP com [tiny_http](https://crates.io/crates/tiny_http); métricas de sistema
  via [sysinfo](https://crates.io/crates/sysinfo); hash [BLAKE3](https://crates.io/crates/blake3).
- O link ao libpam é resolvido em `build.rs` sem exigir o pacote de desenvolvimento.

Testes: `cargo test` exercita scan, quarentena, restauro, purga e a rejeição byte‑a‑byte
de um ficheiro adulterado com ficheiros reais.

---

## Licença

[MIT](LICENSE) © angolardevops
