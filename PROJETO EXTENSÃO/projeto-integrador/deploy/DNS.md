# DNS e certificado público

O domínio raiz `marquezi.com` já responde com um site. Para não substituí-lo, a
implantação recomendada usa `gestao.marquezi.com` para o sistema interno.

Na zona DNS administrada na Name.com, crie somente depois de conhecer o IPv4
público fixo do servidor:

| Tipo | Host | Valor | TTL |
| ---- | ---- | ----- | --- |
| A | `gestao` | `IPV4_PUBLICO_DO_SERVIDOR` | 300 |

Também é possível usar o comando idempotente incluído no projeto. Gere um token
de produção em **Name.com → Settings → API Tokens** e acrescente ao arquivo de
credenciais, sem substituir a senha do painel:

```text
Token API: COLE_O_TOKEN_AQUI
```

Depois execute:

```sh
npm run dns:configure
```

O comando detecta o IPv4 público, não imprime credenciais e se recusa a
sobrescrever um registro conflitante. Contas com autenticação em duas etapas
podem exigir a liberação explícita do acesso à API nas configurações de
segurança da Name.com.

Se o servidor possuir IPv6 público fixo e firewall corretamente configurado,
adicione também um registro `AAAA`. Não publique um IPv6 que não aceite as
portas 80 e 443.

No servidor, libere TCP 80/443 para o Caddy e mantenha a porta 3000 vinculada
apenas a `127.0.0.1`. Inicie a aplicação com `deploy/production.env.example`
adaptado e o Caddy com:

```sh
APP_DOMAIN=gestao.marquezi.com caddy run --config deploy/Caddyfile
```

Quando o DNS já apontar ao servidor, o Caddy solicita e renova automaticamente
o certificado da Let's Encrypt, além de redirecionar HTTP para HTTPS. A emissão
falhará se o domínio não apontar para o servidor ou se as portas 80/443 não
estiverem acessíveis publicamente.

Não troque os registros do domínio raiz nem de `www` sem confirmar que o site
público atual deve ser removido. Não use o proxy da Cloudflare na primeira
emissão; ative-o posteriormente apenas se a arquitetura for revisada para isso.
