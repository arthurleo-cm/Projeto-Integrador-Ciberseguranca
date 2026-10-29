import { z } from "zod";
z.config(z.locales.pt());
const forbiddenControl =
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/;
const singleLine = (schema) =>
  schema.refine((value) => !/[\r\n]/.test(value) && !forbiddenControl.test(value), {
    message: "Não use caracteres de controle neste campo.",
  });
const text = (max) => singleLine(z.string().trim().min(1).max(max));
const optional = (max) => singleLine(z.string().trim().max(max).default(""));
const optionalMultiline = (max) =>
  z
    .string()
    .trim()
    .max(max)
    .default("")
    .refine((value) => !forbiddenControl.test(value), {
      message: "O campo contém caracteres de controle inválidos.",
    });
const password = z
  .string()
  .min(12)
  .max(128)
  .refine((value) => !/[\r\n]/.test(value) && !forbiddenControl.test(value), {
    message: "A senha contém caracteres de controle inválidos.",
  })
  .refine(
    (value) =>
      !/^(.)\1+$/.test(value) &&
      ![
        "123456789012",
        "administrador",
        "senha12345678",
        "password1234",
        "qwertyuiop12",
      ].includes(value.toLowerCase()),
    { message: "Escolha uma senha menos previsível." },
  );
export function validDocument(s) {
  if (!/^\d{11}$|^\d{14}$/.test(s) || /^(\d)\1+$/.test(s)) return false;
  const digit = (part, weights) => {
    const n =
      part.split("").reduce((sum, d, i) => sum + Number(d) * weights[i], 0) %
      11;
    return n < 2 ? 0 : 11 - n;
  };
  const base = s.length - 2;
  const weights = (n) =>
    s.length === 11
      ? Array.from({ length: n }, (_, i) => n + 1 - i)
      : Array.from({ length: n }, (_, i) => ((n - 1 - i) % 8) + 2);
  return (
    +s[base] === digit(s.slice(0, base), weights(base)) &&
    +s[base + 1] === digit(s.slice(0, base + 1), weights(base + 1))
  );
}
export function validCNJ(value) {
  const digits = String(value).replace(/\D/g, "");
  if (!/^\d{20}$/.test(digits)) return false;
  const base = digits.slice(0, 7) + digits.slice(9);
  const expected = 98n - (BigInt(base + "00") % 97n);
  return digits.slice(7, 9) === String(expected).padStart(2, "0");
}
export const CONTACT_TYPES = [
  "TELEFONE",
  "WHATSAPP",
  "EMAIL",
  "INSTAGRAM",
  "LINKEDIN",
  "FACEBOOK",
  "SITE",
  "OUTRO",
];
const validHttpUrl = (value) => {
  try {
    const url = new URL(value);
    return (
      ["http:", "https:"].includes(url.protocol) &&
      !url.username &&
      !url.password
    );
  } catch {
    return false;
  }
};
const contact = z
  .object({
    tipo: z.enum(CONTACT_TYPES),
    valor: text(180),
    principal: z.boolean(),
  })
  .strict()
  .superRefine((v, c) => {
    const valid =
      v.tipo === "EMAIL"
        ? z.email().safeParse(v.valor).success
        : ["TELEFONE", "WHATSAPP"].includes(v.tipo)
          ? /^\+?[\d().\s-]{10,22}$/.test(v.valor) &&
            /^\+?\d{10,15}$/.test(v.valor.replace(/[().\s-]/g, ""))
          : ["LINKEDIN", "FACEBOOK", "SITE"].includes(v.tipo)
            ? validHttpUrl(v.valor)
            : v.tipo === "INSTAGRAM"
              ? /^@?[a-zA-Z0-9._]{1,30}$/.test(v.valor) || validHttpUrl(v.valor)
              : true;
    if (!valid)
      c.addIssue({ code: "custom", message: "Contato inválido." });
  })
  .transform((v) => ({
    ...v,
    valor:
      v.tipo === "EMAIL"
        ? v.valor.toLowerCase()
        : ["TELEFONE", "WHATSAPP"].includes(v.tipo)
          ? v.valor.replace(/[().\s-]/g, "")
          : v.valor,
  }));
const address = z
  .object({
    tipo: z.enum(["RESIDENCIAL", "COMERCIAL", "OUTRO"]),
    cep: z.string().regex(/^(\d{8})?$/),
    logradouro: text(150),
    numero: text(15),
    complemento: optional(100),
    bairro: optional(100),
    cidade: text(100),
    uf: z.enum(
      "AC AL AP AM BA CE DF ES GO MA MT MS MG PA PB PR PE PI RJ RN RS RO RR SC SP SE TO".split(
        " ",
      ),
    ),
    principal: z.boolean(),
  })
  .strict();
export const clientSchema = z
  .object({
    tipo_pessoa: z.enum(["PF", "PJ"]),
    nome: text(150),
    cpf_cnpj: z
      .string()
      .max(18)
      .transform((s) => s.replace(/[.\-/\s]/g, "")),
    data_nascimento: optional(10),
    observacoes: optionalMultiline(10000),
    ativo: z.boolean(),
    versao: z.number().int().positive().optional(),
    contatos: z.array(contact).max(30),
    enderecos: z.array(address).max(20),
  })
  .strict()
  .superRefine((v, c) => {
    const error = (message) => c.addIssue({ code: "custom", message });
    if (
      v.cpf_cnpj &&
      (!validDocument(v.cpf_cnpj) ||
        v.cpf_cnpj.length !== (v.tipo_pessoa === "PF" ? 11 : 14))
    )
      error("CPF/CNPJ inválido para o tipo de pessoa.");
    if (
      v.data_nascimento &&
      (v.tipo_pessoa !== "PF" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(v.data_nascimento) ||
        !Number.isFinite(Date.parse(v.data_nascimento)) ||
        new Date(v.data_nascimento).toISOString().slice(0, 10) !==
          v.data_nascimento ||
        v.data_nascimento > new Date().toISOString().slice(0, 10))
    )
      error("Data de nascimento inválida.");
    for (const tipo of CONTACT_TYPES)
      if (v.contatos.filter((x) => x.tipo === tipo && x.principal).length > 1)
        error("Escolha um contato principal por tipo.");
    if (v.enderecos.filter((x) => x.principal).length > 1)
      error("Escolha um endereço principal.");
    if (
      new Set(v.contatos.map((x) => x.tipo + ":" + x.valor.toLowerCase()))
        .size !== v.contatos.length
    )
      error("Contato duplicado.");
  });
export const userSchema = z
  .object({
    nome: text(150),
    email: z
      .email()
      .max(180)
      .transform((s) => s.toLowerCase()),
    perfil: z.enum(["ADMINISTRADOR", "OPERADOR"]),
    ativo: z.boolean(),
    senha: password.optional(),
  })
  .strict();
export const loginSchema = z
  .object({
    email: z.email().max(180).transform((value) => value.toLowerCase()),
    senha: z.string().min(1).max(128),
  })
  .strict();
export const mfaVerifySchema = z
  .object({
    desafio: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    codigo: z.string().regex(/^\d{6}$/),
  })
  .strict();
export const mfaChallengeSchema = z
  .object({ desafio: z.string().regex(/^[A-Za-z0-9_-]{43}$/) })
  .strict();
export const passwordChangeSchema = z
  .object({ atual: z.string().min(1).max(128), nova: password })
  .strict()
  .refine((value) => value.atual !== value.nova, {
    path: ["nova"],
    message: "A nova senha deve ser diferente da senha atual.",
  });
export const deleteClientSchema = z
  .object({ versao: z.number().int().positive() })
  .strict();
export const PROCESS_STATUS = [
  "EM_ANALISE",
  "EM_ANDAMENTO",
  "AGUARDANDO_AUDIENCIA",
  "AGUARDANDO_DECISAO",
  "SUSPENSO",
  "EM_RECURSO",
  "ENCERRADO",
  "ARQUIVADO",
];
export const PROCESS_TYPES = {
  CIVEL: [
    "COBRANCA",
    "RESPONSABILIDADE_CIVIL",
    "OBRIGACAO_DE_FAZER",
    "EXECUCAO",
    "OUTRO",
  ],
  FAMILIA: ["DIVORCIO", "GUARDA", "ALIMENTOS", "UNIAO_ESTAVEL", "OUTRO"],
  CONSUMIDOR: [
    "INDENIZACAO",
    "VICIO_PRODUTO",
    "NEGATIVACAO",
    "REVISAO_CONTRATUAL",
    "OUTRO",
  ],
  TRABALHISTA: [
    "RECLAMACAO",
    "RESCISAO",
    "VERBAS_TRABALHISTAS",
    "ACIDENTE_TRABALHO",
    "OUTRO",
  ],
  PREVIDENCIARIO: [
    "APOSENTADORIA",
    "BENEFICIO_INCAPACIDADE",
    "BPC_LOAS",
    "REVISAO_BENEFICIO",
    "OUTRO",
  ],
  EMPRESARIAL: [
    "CONTRATOS",
    "SOCIETARIO",
    "RECUPERACAO_CREDITO",
    "FALENCIA",
    "OUTRO",
  ],
  TRIBUTARIO: [
    "EXECUCAO_FISCAL",
    "REPETICAO_INDEBITO",
    "ANULATORIA",
    "CONSULTORIA",
    "OUTRO",
  ],
  ADMINISTRATIVO: [
    "SERVIDOR_PUBLICO",
    "LICITACAO",
    "IMPROBIDADE",
    "DESAPROPRIACAO",
    "OUTRO",
  ],
  IMOBILIARIO: ["DESPEJO", "USUCAPIAO", "LOCACAO", "REGULARIZACAO", "OUTRO"],
  SUCESSOES: ["INVENTARIO", "ARROLAMENTO", "TESTAMENTO", "PARTILHA", "OUTRO"],
  OUTRO: ["OUTRO"],
};
const calendarDate = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine(
    (value) =>
      Number.isFinite(Date.parse(value)) &&
      new Date(value).toISOString().slice(0, 10) === value,
    { message: "Data inválida." },
  );
const exactDate = calendarDate.refine(
  (value) => value <= new Date().toISOString().slice(0, 10),
  { message: "A data não pode estar no futuro." },
);
export const processSchema = z
  .object({
    id_cliente: z.number().int().positive(),
    numero_cnj: z
      .string()
      .max(30)
      .transform((value) => value.replace(/\D/g, ""))
      .refine(validCNJ, { message: "Número CNJ inválido." }),
    titulo: text(180),
    status: z.enum(PROCESS_STATUS),
    ramo: z.enum(Object.keys(PROCESS_TYPES)),
    tipificacao: text(60),
    situacao: z.enum(["ATIVO", "ENCERRADO", "ARQUIVADO"]),
    data_abertura: exactDate,
    valor_estimado_centavos: z.number().int().min(0).max(999999999999),
    previsao_recebimento: z.union([z.literal(""), calendarDate]).default(""),
    observacoes: optionalMultiline(10000),
    versao: z.number().int().positive().optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (!PROCESS_TYPES[value.ramo].includes(value.tipificacao))
      context.addIssue({
        code: "custom",
        path: ["tipificacao"],
        message: "Tipificação incompatível com o ramo selecionado.",
      });
    if (value.status === "ENCERRADO" && value.situacao !== "ENCERRADO")
      context.addIssue({
        code: "custom",
        message: "Processo encerrado deve ter situação encerrada.",
      });
    if (value.status === "ARQUIVADO" && value.situacao !== "ARQUIVADO")
      context.addIssue({
        code: "custom",
        message: "Processo arquivado deve ter situação arquivada.",
      });
    if (value.situacao === "ENCERRADO" && value.status !== "ENCERRADO")
      context.addIssue({
        code: "custom",
        message: "Situação encerrada exige status encerrado.",
      });
    if (value.situacao === "ARQUIVADO" && value.status !== "ARQUIVADO")
      context.addIssue({
        code: "custom",
        message: "Situação arquivada exige status arquivado.",
      });
  });
export const receiptSchema = z
  .object({
    valor_centavos: z.number().int().positive().max(999999999999),
    data_recebimento: exactDate,
    observacao: optionalMultiline(1000),
  })
  .strict();
export const preferencesSchema = z
  .object({
    tema: z.enum(["CLARO", "ESCURO", "SISTEMA"]),
    fonte: z.enum(["NORMAL", "GRANDE", "MUITO_GRANDE"]),
    alto_contraste: z.boolean(),
  })
  .strict();
export const processFileSchema = z.object({ titulo: text(150) }).strict();
export const documentSchema = z
  .object({
    titulo: text(150),
    tipo_documento: z.enum([
      "IDENTIFICACAO",
      "PROCURACAO",
      "CONTRATO",
      "OUTRO",
    ]),
  })
  .strict();
