import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

process.umask(0o077);
const dataDirectory = resolve(process.env.DATA_DIR || "data");
const tlsDirectory = resolve(dataDirectory, "tls");
const certificateFile = resolve(tlsDirectory, "localhost-cert.pem");
const privateKeyFile = resolve(tlsDirectory, "localhost-key.pem");
const renew = process.argv.includes("--renew");

if ((existsSync(certificateFile) || existsSync(privateKeyFile)) && !renew) {
  console.error(
    "O certificado local já existe. Use npm run setup:tls -- --renew para renová-lo.",
  );
  process.exit(1);
}

mkdirSync(tlsDirectory, { recursive: true, mode: 0o700 });
const configFile = resolve(tlsDirectory, ".openssl-localhost.cnf");
writeFileSync(
  configFile,
  `[req]\n` +
    `distinguished_name=subject\n` +
    `x509_extensions=extensions\n` +
    `prompt=no\n` +
    `[subject]\n` +
    `CN=localhost\n` +
    `[extensions]\n` +
    `basicConstraints=critical,CA:FALSE\n` +
    `keyUsage=critical,digitalSignature,keyEncipherment\n` +
    `extendedKeyUsage=serverAuth\n` +
    `subjectAltName=@names\n` +
    `[names]\n` +
    `DNS.1=localhost\n` +
    `IP.1=127.0.0.1\n` +
    `IP.2=::1\n`,
  { mode: 0o600 },
);

try {
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:3072",
      "-sha256",
      "-nodes",
      "-days",
      "365",
      "-config",
      configFile,
      "-keyout",
      privateKeyFile,
      "-out",
      certificateFile,
    ],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  chmodSync(tlsDirectory, 0o700);
  chmodSync(privateKeyFile, 0o600);
  chmodSync(certificateFile, 0o600);
  console.log(`HTTPS local configurado. Certificado: ${certificateFile}`);
  console.log("Acesse https://localhost:3000 e confie no certificado local.");
} catch (error) {
  console.error(
    error.code === "ENOENT"
      ? "OpenSSL não foi encontrado. Instale-o e execute o comando novamente."
      : "Não foi possível gerar o certificado TLS local.",
  );
  process.exit(1);
}
