"use strict";
// Opcional: só formata e confere CPF/CNPJ, CNJ, OAB e CEP enquanto o usuário digita.
// Sem este arquivo o sistema funciona igual; o Python valida tudo de novo ao salvar.

const digits = (v) => v.replace(/\D/g, "");

function maskDoc(v) {
  const n = digits(v).slice(0, 14);
  if (n.length <= 11) {
    return n.replace(/^(\d{3})(\d)/, "$1.$2").replace(/^(\d{3})\.(\d{3})(\d)/, "$1.$2.$3").replace(/(\d{3})(\d{1,2})$/, "$1-$2");
  }
  return n.replace(/^(\d{2})(\d)/, "$1.$2").replace(/^(\d{2})\.(\d{3})(\d)/, "$1.$2.$3")
    .replace(/\.(\d{3})(\d)/, ".$1/$2").replace(/(\d{4})(\d)/, "$1-$2");
}

function validDoc(s) {
  if (!/^(\d{11}|\d{14})$/.test(s) || /^(\d)\1+$/.test(s)) return false;
  const calc = (part) => {
    const w = s.length === 11 ? (i) => part.length + 1 - i : (i) => ((part.length - 1 - i) % 8) + 2;
    const r = [...part].reduce((sum, d, i) => sum + Number(d) * w(i), 0) % 11;
    return r < 2 ? 0 : 11 - r;
  };
  const b = s.length - 2;
  return Number(s[b]) === calc(s.slice(0, b)) && Number(s[b + 1]) === calc(s.slice(0, b + 1));
}

function maskCnj(v) {
  return digits(v).slice(0, 20)
    .replace(/^(\d{7})(\d)/, "$1-$2")
    .replace(/^(\d{7})-(\d{2})(\d)/, "$1-$2.$3")
    .replace(/^(\d{7})-(\d{2})\.(\d{4})(\d)/, "$1-$2.$3.$4")
    .replace(/^(\d{7})-(\d{2})\.(\d{4})\.(\d)(\d)/, "$1-$2.$3.$4.$5")
    .replace(/^(\d{7})-(\d{2})\.(\d{4})\.(\d)\.(\d{2})(\d)/, "$1-$2.$3.$4.$5.$6");
}

function validCnj(n) {
  const base = n.slice(0, 7) + n.slice(9);
  return n.slice(7, 9) === String(98n - (BigInt(base + "00") % 97n)).padStart(2, "0");
}

function check(input) {
  const n = digits(input.value);
  let msg = "";
  if (input.dataset.mask === "doc" && n) {
    msg = n.length !== 11 && n.length !== 14 ? "CPF tem 11 dígitos e CNPJ tem 14."
      : !validDoc(n) ? (n.length === 11 ? "CPF inválido." : "CNPJ inválido.") : "";
  }
  if (input.dataset.mask === "cnj" && n) {
    msg = n.length !== 20 ? "Complete os 20 dígitos do número CNJ." : !validCnj(n) ? "Número CNJ inválido." : "";
  }
  input.setCustomValidity(msg);
  const out = input.parentElement.querySelector("[data-error]");
  if (out) out.textContent = msg;
}

document.addEventListener("input", (ev) => {
  const el = ev.target, mask = el.dataset && el.dataset.mask;
  if (mask === "doc") el.value = maskDoc(el.value);
  else if (mask === "cnj") el.value = maskCnj(el.value);
  else if (mask === "oab") el.value = el.value.toUpperCase().replace(/[^0-9A-Z/]/g, "").slice(0, 10);
  else if (mask === "digits") el.value = digits(el.value);
  else return;
  check(el);
});

document.querySelectorAll('[data-mask="doc"], [data-mask="cnj"]').forEach((el) => { if (el.value) check(el); });
