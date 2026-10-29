import { randomBytes } from "node:crypto";

process.umask(0o077);
if (!process.argv.includes("--confirm-demo-data"))
  throw new Error(
    "Esta operação inclui dados fictícios. Execute: npm run seed:demo -- --confirm-demo-data",
  );

const {
  db,
  pack,
  unpack,
  index,
  hashPassword,
  transaction,
  audit,
} = await import("../server/store.js");
const { clientSchema, userSchema, processSchema } = await import(
  "../server/validation.js"
);

const admin = db
  .prepare(
    "SELECT id_usuario FROM usuarios WHERE ativo=1 AND perfil='ADMINISTRADOR' ORDER BY id_usuario LIMIT 1",
  )
  .get();
if (!admin) {
  db.close();
  throw new Error("Execute npm run setup e crie um administrador primeiro.");
}

const users = [
  { nome: "Ana Rodrigues", email: "ana.rodrigues@marquezi.example" },
  { nome: "Carlos Mendes", email: "carlos.mendes@marquezi.example" },
  { nome: "Júlia Nascimento", email: "julia.nascimento@marquezi.example" },
];
const credentials = [];
for (const entry of users) {
  if (
    db.prepare("SELECT 1 FROM usuarios WHERE email_indice=?").get(index(entry.email))
  )
    continue;
  const senha = `Demo-2026-${randomBytes(12).toString("base64url")}`;
  const user = userSchema.parse({
    ...entry,
    senha,
    perfil: "OPERADOR",
    ativo: true,
  });
  credentials.push({ ...user, senha, senha_hash: await hashPassword(senha) });
}

const clients = [
  {
    nome: "Marina Alves",
    tipo_pessoa: "PF",
    data_nascimento: "1988-04-12",
    contatos: [
      { tipo: "EMAIL", valor: "marina.alves@example.com", principal: true },
      { tipo: "WHATSAPP", valor: "+5511999990001", principal: true },
      { tipo: "INSTAGRAM", valor: "@marina.exemplo", principal: true },
    ],
    enderecos: [
      {
        tipo: "RESIDENCIAL",
        cep: "01310100",
        logradouro: "Rua Exemplo",
        numero: "120",
        complemento: "Apto. 31",
        bairro: "Bela Vista",
        cidade: "São Paulo",
        uf: "SP",
        principal: true,
      },
    ],
  },
  {
    nome: "João Carvalho",
    tipo_pessoa: "PF",
    data_nascimento: "1979-11-23",
    contatos: [
      { tipo: "EMAIL", valor: "joao.carvalho@example.com", principal: true },
    ],
    enderecos: [],
  },
  {
    nome: "Beatriz Lima",
    tipo_pessoa: "PF",
    data_nascimento: "1995-07-08",
    ativo: false,
    contatos: [
      { tipo: "EMAIL", valor: "beatriz.lima@example.com", principal: true },
    ],
    enderecos: [],
  },
  {
    nome: "Horizonte Tecnologia Ltda.",
    tipo_pessoa: "PJ",
    contatos: [
      { tipo: "EMAIL", valor: "juridico@horizonte.example", principal: true },
      {
        tipo: "LINKEDIN",
        valor: "https://www.linkedin.com/company/horizonte-example",
        principal: true,
      },
    ],
    enderecos: [
      {
        tipo: "COMERCIAL",
        cep: "13010000",
        logradouro: "Avenida Modelo",
        numero: "850",
        complemento: "Conjunto 42",
        bairro: "Centro",
        cidade: "Campinas",
        uf: "SP",
        principal: true,
      },
    ],
  },
  {
    nome: "Café Aurora Comércio Ltda.",
    tipo_pessoa: "PJ",
    contatos: [
      { tipo: "EMAIL", valor: "contato@cafeaurora.example", principal: true },
      { tipo: "SITE", valor: "https://cafeaurora.example", principal: true },
    ],
    enderecos: [],
  },
].map((client) =>
  clientSchema.parse({
    cpf_cnpj: "",
    data_nascimento: "",
    observacoes:
      "Cadastro de demonstração com informações inteiramente fictícias.",
    ativo: true,
    contatos: [],
    enderecos: [],
    ...client,
  }),
);

const existingClientNames = new Set(
  db
    .prepare("SELECT dados FROM clientes")
    .all()
    .map((row) => unpack(row.dados, "cliente").nome),
);

let usersCreated = 0;
let clientsCreated = 0;
let processesCreated = 0;
transaction(() => {
  for (const user of credentials) {
    const row = db
      .prepare(
        "INSERT INTO usuarios(dados,email_indice,senha_hash,perfil,ativo) VALUES(?,?,?,?,1)",
      )
      .run(
        pack(
          { nome: user.nome, email: user.email },
          "usuario",
        ),
        index(user.email),
        user.senha_hash,
        "OPERADOR",
      );
    audit(admin.id_usuario, "CADASTRO", "usuarios", Number(row.lastInsertRowid));
    usersCreated += 1;
  }
  for (const client of clients) {
    if (existingClientNames.has(client.nome)) continue;
    const { contatos, enderecos, ativo, versao, ...data } = client;
    const row = db
      .prepare("INSERT INTO clientes(dados,documento_indice,ativo) VALUES(?,NULL,?)")
      .run(pack(data, "cliente"), +ativo);
    const clientId = Number(row.lastInsertRowid);
    for (const contact of contatos) {
      const value =
        contact.tipo === "EMAIL" ? contact.valor.toLowerCase() : contact.valor;
      db.prepare(
        "INSERT INTO contatos(id_cliente,tipo,dados,valor_indice,principal) VALUES(?,?,?,?,?)",
      ).run(
        clientId,
        contact.tipo,
        pack({ valor: value }, "contato"),
        index(value),
        +contact.principal,
      );
    }
    for (const { principal, ...address } of enderecos)
      db.prepare(
        "INSERT INTO enderecos(id_cliente,dados,principal) VALUES(?,?,?)",
      ).run(clientId, pack(address, "endereco"), +principal);
    audit(admin.id_usuario, "CADASTRO", "clientes", clientId);
    clientsCreated += 1;
  }
  const clientIds = new Map(
    db
      .prepare("SELECT id_cliente,dados FROM clientes")
      .all()
      .map((row) => [unpack(row.dados, "cliente").nome, row.id_cliente]),
  );
  for (const client of clients) {
    const clientId = clientIds.get(client.nome);
    for (const contact of client.contatos)
      db.prepare(
        "INSERT OR IGNORE INTO contatos(id_cliente,tipo,dados,valor_indice,principal) VALUES(?,?,?,?,?)",
      ).run(
        clientId,
        contact.tipo,
        pack({ valor: contact.valor }, "contato"),
        index(contact.valor),
        +contact.principal,
      );
  }
  const cnj = (sequence, year, segment, court, origin) => {
    const base =
      String(sequence).padStart(7, "0") +
      String(year) +
      String(segment) +
      String(court).padStart(2, "0") +
      String(origin).padStart(4, "0");
    const check = String(98n - (BigInt(base + "00") % 97n)).padStart(2, "0");
    return base.slice(0, 7) + check + base.slice(7);
  };
  const processes = [
    {
      cliente: "Marina Alves",
      numero_cnj: cnj(1234, 2026, 8, 26, 100),
      titulo: "Cobrança de obrigação contratual",
      status: "EM_ANDAMENTO",
      ramo: "CIVEL",
      tipificacao: "COBRANCA",
      situacao: "ATIVO",
      data_abertura: "2026-02-03",
      valor_estimado_centavos: 1850000,
      observacoes: "Processo e valores inteiramente fictícios para demonstração.",
      recebimento: 350000,
    },
    {
      cliente: "Horizonte Tecnologia Ltda.",
      numero_cnj: cnj(2781, 2026, 8, 26, 101),
      titulo: "Revisão de contrato empresarial",
      status: "EM_ANALISE",
      ramo: "EMPRESARIAL",
      tipificacao: "CONTRATOS",
      situacao: "ATIVO",
      data_abertura: "2026-03-18",
      valor_estimado_centavos: 7800000,
      observacoes: "Processo fictício para treinamento da equipe.",
    },
    {
      cliente: "João Carvalho",
      numero_cnj: cnj(3150, 2025, 4, 3, 6100),
      titulo: "Revisão de benefício previdenciário",
      status: "AGUARDANDO_DECISAO",
      ramo: "PREVIDENCIARIO",
      tipificacao: "REVISAO_BENEFICIO",
      situacao: "ATIVO",
      data_abertura: "2025-11-10",
      valor_estimado_centavos: 2400000,
      observacoes: "Dados fictícios; não correspondem a processo judicial real.",
    },
  ];
  for (const seed of processes) {
    if (
      db
        .prepare("SELECT 1 FROM processos WHERE numero_indice=?")
        .get(index(seed.numero_cnj))
    )
      continue;
    const { recebimento, cliente, ...processData } = seed;
    const clientId = clientIds.get(cliente);
    const value = processSchema.parse({
      ...processData,
      id_cliente: clientId,
    });
    const row = db
      .prepare(
        "INSERT INTO processos(id_cliente,numero_indice,dados,status,ramo,tipificacao,situacao,data_abertura,valor_estimado_centavos) VALUES(?,?,?,?,?,?,?,?,?)",
      )
      .run(
        value.id_cliente,
        index(value.numero_cnj),
        pack(
          {
            numero_cnj: value.numero_cnj,
            titulo: value.titulo,
            observacoes: value.observacoes,
            previsao_recebimento: value.previsao_recebimento,
          },
          "processo",
        ),
        value.status,
        value.ramo,
        value.tipificacao,
        value.situacao,
        value.data_abertura,
        value.valor_estimado_centavos,
      );
    const processId = Number(row.lastInsertRowid);
    db.prepare(
      "INSERT INTO historico_processos(id_processo,id_usuario,dados) VALUES(?,?,?)",
    ).run(
      processId,
      admin.id_usuario,
      pack(
        { evento: "PROCESSO_CADASTRADO", status_atual: value.status },
        `historico:${processId}`,
      ),
    );
    if (recebimento)
      db.prepare(
        "INSERT INTO recebimentos(id_processo,id_usuario,dados,valor_centavos,data_recebimento) VALUES(?,?,?,?,?)",
      ).run(
        processId,
        admin.id_usuario,
        pack(
          { observacao: "Recebimento fictício de demonstração" },
          `recebimento:${processId}`,
        ),
        recebimento,
        "2026-03-05",
      );
    audit(admin.id_usuario, "CADASTRO", "processos", processId);
    processesCreated += 1;
  }
});

console.log(
  `Demonstração pronta: ${usersCreated} usuários, ${clientsCreated} clientes e ${processesCreated} processos criados.`,
);
if (credentials.length) {
  console.log("Credenciais geradas (guarde agora; as senhas não são recuperáveis):");
  for (const user of credentials)
    console.log(`- ${user.nome}: ${user.email} / ${user.senha}`);
} else {
  console.log("Os usuários de demonstração já existiam; nenhuma senha foi alterada.");
}
console.log("Todos os usuários de demonstração têm somente o perfil OPERADOR.");
db.close();
