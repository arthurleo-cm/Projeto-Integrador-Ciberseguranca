import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const ipv4Parts = (address) => address.split(".").map(Number);

export function isPublicIp(address) {
  const family = isIP(address);
  if (family === 4) {
    const [a, b, c] = ipv4Parts(address);
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0 && c === 0) ||
      (a === 192 && b === 0 && c === 2) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224
    );
  }
  if (family === 6) {
    const value = address.toLowerCase().split("%", 1)[0];
    if (value.startsWith("::ffff:"))
      return isPublicIp(value.slice("::ffff:".length));
    if (!/^[23]/.test(value)) return false;
    return !(
      value.startsWith("2001:db8:") ||
      value === "2001:db8::" ||
      value.startsWith("2001:0:") ||
      value.startsWith("2001:2:") ||
      value.startsWith("2001:10:") ||
      value.startsWith("2001:20:")
    );
  }
  return false;
}

export async function resolvePublicHost(host) {
  const hostname = String(host || "").toLowerCase().replace(/\.$/, "");
  if (
    !hostname ||
    hostname.length > 253 ||
    (!isIP(hostname) &&
      !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
        hostname,
      ))
  )
    throw new Error("Destino de rede inválido.");

  const addresses = isIP(hostname)
    ? [{ address: hostname, family: isIP(hostname) }]
    : await lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => !isPublicIp(address)))
    throw new Error("Destino de rede privado ou reservado recusado.");
  const selected =
    addresses.find(({ family }) => family === 4) || addresses[0];
  return {
    hostname,
    address: selected.address,
    family: selected.family,
    addresses: addresses.map(({ address, family }) => ({ address, family })),
  };
}
