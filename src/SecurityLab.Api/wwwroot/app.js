// === Security Lab, frontend logika ===
// Svaki napad je opisan jednim "config" objektom u ATTACKS mapi (po id-ju).
// Novi napad na frontu = dodam jedan unos ovde.

const ATTACKS = {

  "path-traversal": {
    intro: `
      <p><b>Path Traversal</b> znači čitanje fajlova VAN dozvoljenog foldera tako što se u ime
      fajla ubaci <code>../</code> (izađi jedan folder gore).</p>
      <p>Servis servira fakture iz foldera <code>App_Data/sales-docs</code>. Probaj prvo normalan
      fajl, pa onda napad koji čita tajni fajl izvan foldera.</p>`,
    controls: [
      { type: "text", id: "file", label: "Ime fajla (parametar ?file=)",
        value: "../secret/credentials.txt",
        hint: "Normalno: invoice-1001.txt  •  Napad: ../secret/credentials.txt" }
    ],
    run: (mode, v) => apiGet(`/api/path-traversal/${mode}?file=${encodeURIComponent(v.file)}`)
  },

  "command-injection": {
    intro: `
      <p><b>Command Injection</b> znači ubacivanje sopstvenih sistemskih komandi kroz polje koje
      aplikacija prosleđuje shell-u.</p>
      <p>Alatka "proverava dostupnost host-a". Probaj normalan host, pa onda napad koji dopiše
      dodatnu komandu posle <code>;</code>.</p>`,
    controls: [
      { type: "text", id: "host", label: "Host (parametar ?host=)",
        value: "x && whoami",
        hint: "Normalno: example.com  •  Napad: x && whoami  (radi i na Linux i na Windows)" }
    ],
    run: (mode, v) => apiGet(`/api/command-injection/${mode}?host=${encodeURIComponent(v.host)}`)
  },

  "file-upload": {
    intro: `
      <p><b>Nesiguran upload</b>: server prima bilo koji fajl i servira ga nazad. Ako ubacimo
      <code>.html</code> sa <code>&lt;script&gt;</code>, dobijamo izvršni sadržaj (stored XSS).</p>
      <p>Dugme ispod pravi mali "zlonamerni" HTML fajl i šalje ga. Na ranjivoj grani dobićeš
      URL koji možeš da otvoriš; na bezbednoj ga WAF blokira.</p>`,
    controls: [
      { type: "select", id: "kind", label: "Šta šaljemo",
        options: [
          { value: "evil-html", text: "evil.html sa <script> (napad)" },
          { value: "double-ext", text: "shell.php.png (dvostruka ekstenzija)" },
          { value: "fake-png", text: "slika.png ali sadržaj je skripta" },
          { value: "clean-png", text: "stvarni mali PNG (čist fajl)" }
        ] }
    ],
    run: (mode, v) => {
      const { blob, name } = buildUploadFile(v.kind);
      const fd = new FormData();
      fd.append("file", blob, name);
      return apiSend(`/api/file-upload/${mode}`, fd);
    }
  },

  "jwt": {
    intro: `
      <p><b>JWT</b> token nosi tvoju ulogu (<code>role</code>). Ako server loše proverava
      <b>potpis</b>, napadač može sam da iskuje <i>admin</i> token.</p>
      <p>Klik pokreće "alat" koji automatski proba dve forge tehnike: <code>alg:none</code>
      (token bez potpisa) i HS256 sa slabim ključem <code>secret</code>. Ranjiva grana ih
      prihvata, bezbedna odbija.</p>`,
    controls: [],
    run: (mode) => apiGet(`/api/jwt/${mode}/attack`)
  },

  "toctou": {
    intro: `
      <p><b>TOCTOU / race condition</b>: kartica ima 100 RSD. Endpoint prvo proveri pa oduzme.
      Ako pošalješ više zahteva istovremeno, svi vide 100 i svi potroše, pa imaš duplo trošenje.</p>
      <p>Pokreni više istovremenih zahteva i uporedi koliko kupovina prođe.</p>`,
    controls: [
      { type: "number", id: "concurrency", label: "Broj istovremenih zahteva", value: "10",
        hint: "Balans je 100, svaka kupovina košta 100, sme da prođe samo JEDNA." }
    ],
    run: (mode, v) => apiGet(`/api/toctou/${mode}/run?concurrency=${encodeURIComponent(v.concurrency)}`)
  },

  "host-header": {
    intro: `
      <p><b>Host Header Injection</b>: link za reset lozinke se pravi od domena iz zahteva
      (<code>X-Forwarded-Host</code>). Napadač podmetne svoj domen i žrtvin reset-token ode njemu.</p>
      <p>Unesi "napadački" host i pogledaj kuda pokazuje link na svakoj grani.</p>`,
    controls: [
      { type: "text", id: "host", label: "X-Forwarded-Host (napadački domen)",
        value: "evil.attacker.com", hint: "Bezbedna grana prihvata samo domene sa bele liste." }
    ],
    run: (mode, v) => apiGet(`/api/host-header/${mode}/reset-link`, { "X-Forwarded-Host": v.host })
  },

  "prototype-pollution": {
    intro: `
      <p><b>Prototype Pollution</b> (JavaScript): nesiguran "deep merge" koji kopira ključ
      <code>__proto__</code> menja <code>Object.prototype</code>, pa SVI objekti odjednom
      dobiju npr. <code>isAdmin=true</code>.</p>
      <p>Demo se izvršava ovde u browseru. Posle napada pravimo prazan objekat
      <code>{}</code> i proveravamo da li je "postao" admin.</p>`,
    controls: [
      { type: "text", id: "payload", label: "Zlonameran JSON",
        value: '{"__proto__":{"isAdmin":true}}', hint: "Ranjivi merge kopira __proto__; bezbedni ga preskače." }
    ],
    run: (mode, v) => runPrototypePollution(mode, v.payload)
  },

  "graphql": {
    intro: `
      <p><b>GraphQL Injection / curenje podataka</b>: klijent bira koja polja hoće. Ako je
      introspekcija uključena ili nema autorizacije po polju, napadač izvuče šemu i osetljiva
      polja (npr. <code>passwordHash</code>).</p>`,
    controls: [
      { type: "select", id: "q", label: "Upit",
        options: [
          { value: "{ users { id name passwordHash role } }", text: "Traži passwordHash + role (napad)" },
          { value: "{ __schema { types { name fields } } }", text: "Introspekcija šeme (napad)" },
          { value: "{ users { id name } }", text: "Samo javna polja (čist upit)" }
        ] }
    ],
    run: (mode, v) => apiPostJson(`/api/graphql/${mode}`, { query: v.q })
  },

  "oauth": {
    intro: `
      <p><b>OAuth 2.0</b>: server vraća <code>code</code> na <code>redirect_uri</code>. Ako se
      <code>redirect_uri</code> ne proverava, napadač podmetne svoj i <code>code</code> (a sa njim i nalog)
      ode njemu. Nedostatak <code>state</code> = CSRF.</p>`,
    controls: [
      { type: "text", id: "redirect", label: "redirect_uri",
        value: "https://evil.attacker.com/callback", hint: "Bezbedna grana traži tačno registrovan URI." },
      { type: "text", id: "state", label: "state (ostavi prazno da vidiš CSRF zaštitu)", value: "" }
    ],
    run: (mode, v) => apiGet(`/api/oauth/${mode}/authorize?redirect_uri=${encodeURIComponent(v.redirect)}&state=${encodeURIComponent(v.state)}`)
  },

  "supply-chain": {
    intro: `
      <p><b>Supply Chain</b>: ne napada se tvoj kod nego BIBLIOTEKA (npr. <code>axios</code>).
      Zlonamerna verzija paketa pri instalaciji izvrši backdoor koji krade env tajne.</p>
      <p>Ranjiva grana slepo izvrši instaliran paket; bezbedna proverava integritet (lockfile hash).</p>`,
    controls: [],
    run: (mode) => apiGet(`/api/supply-chain/${mode}/install-and-run`)
  },

  "heartbleed": {
    intro: `
      <p><b>Heartbleed</b>: u TLS "heartbeat"-u klijent pošalje poruku i KAŽE koliko je dugačka.
      Bug: server veruje toj dužini. Pošalji "hi" ali reci da je dugačko 200 i server ti vrati i
      susednu memoriju (ključeve, sesije).</p>`,
    controls: [
      { type: "text", id: "payload", label: "Payload", value: "hi" },
      { type: "number", id: "length", label: "Prijavljena dužina (laž)", value: "200",
        hint: "Payload je 2 bajta; ako kažeš 200, ranjiva grana procuri memoriju." }
    ],
    run: (mode, v) => apiGet(`/api/heartbleed/${mode}/heartbeat?payload=${encodeURIComponent(v.payload)}&length=${encodeURIComponent(v.length)}`)
  }

};

// Prototype Pollution: pravi JS demo, izvršava se u browseru.
function runPrototypePollution(mode, payloadStr) {
  let parsed;
  try { parsed = JSON.parse(payloadStr); }
  catch (e) { return Promise.resolve({ request: "(client-side JS)", status: 400, body: { error: "Neispravan JSON: " + e.message } }); }

  const vulnerableMerge = (target, source) => {
    for (const key in source) {
      if (typeof source[key] === "object" && source[key] !== null) {
        if (!target[key]) target[key] = {};
        vulnerableMerge(target[key], source[key]);   // ovde kopira i __proto__ !
      } else {
        target[key] = source[key];
      }
    }
    return target;
  };
  const secureMerge = (target, source) => {
    for (const key in source) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") continue; // blokada
      if (typeof source[key] === "object" && source[key] !== null) {
        if (!target[key]) target[key] = {};
        secureMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  };

  // Očisti eventualno ranije zagađenje pre testa.
  delete Object.prototype.isAdmin;

  if (mode === "vulnerable") vulnerableMerge({}, parsed);
  else secureMerge({}, parsed);

  const freshObject = {};                 // potpuno nevezan objekat
  const polluted = freshObject.isAdmin === true;
  delete Object.prototype.isAdmin;        // počisti za sobom

  return Promise.resolve({
    request: `(client-side JS)  ${mode}Merge({}, ${payloadStr})`,
    status: polluted ? 200 : (mode === "secure" ? 403 : 200),
    body: {
      mode,
      polledObject: "const fresh = {}; fresh.isAdmin",
      result: freshObject.isAdmin,
      blocked: mode === "secure" && !polluted,
      message: polluted
        ? "USPEO NAPAD: i prazan objekat {} sada ima isAdmin=true, zagađen je Object.prototype!"
        : "Object.prototype je čist, __proto__ je preskočen."
    }
  });
}

// === Generička infrastruktura (ne menja se po napadu) ===

const $ = (id) => document.getElementById(id);
let currentId = null;

async function apiGet(url, headers) {
  const res = await fetch(url, headers ? { headers } : undefined);
  const body = await res.json().catch(() => ({}));
  const hdr = headers ? "  " + Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("  ") : "";
  return { request: `GET ${url}${hdr}`, status: res.status, body };
}

async function apiPostJson(url, obj) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(obj)
  });
  const body = await res.json().catch(() => ({}));
  return { request: `POST ${url}\n${JSON.stringify(obj)}`, status: res.status, body };
}

async function apiSend(url, formData) {
  const res = await fetch(url, { method: "POST", body: formData });
  const body = await res.json().catch(() => ({}));
  return { request: `POST ${url}  (multipart/form-data)`, status: res.status, body };
}

function buildUploadFile(kind) {
  switch (kind) {
    case "evil-html":
      return { blob: new Blob([`<html><body><script>alert('XSS - izvrsen kod sa servera!')<\/script></body></html>`], { type: "text/html" }), name: "evil.html" };
    case "double-ext":
      return { blob: new Blob([`<?php echo 'shell'; ?>`], { type: "image/png" }), name: "shell.php.png" };
    case "fake-png":
      return { blob: new Blob([`<script>alert('not a png')<\/script>`], { type: "image/png" }), name: "slika.png" };
    case "clean-png":
    default: {
      // Najmanji validan PNG (1x1 transparentni piksel).
      const b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return { blob: new Blob([bytes], { type: "image/png" }), name: "slika.png" };
    }
  }
}

function renderControls(cfg) {
  const c = $("controls");
  c.innerHTML = "";
  for (const ctrl of cfg.controls) {
    const wrap = document.createElement("div");
    const label = `<label class="block text-sm font-semibold text-slate-700 mb-1">${ctrl.label}</label>`;
    if (ctrl.type === "text" || ctrl.type === "number") {
      wrap.innerHTML = `${label}
        <input id="ctrl-${ctrl.id}" type="${ctrl.type === "number" ? "number" : "text"}" value="${escapeHtml(ctrl.value || "")}"
          class="w-full border border-slate-300 rounded-lg px-3 py-2 font-mono text-sm focus:ring-2 focus:ring-slate-500 focus:outline-none" />
        ${ctrl.hint ? `<p class="text-xs text-slate-400 mt-1">${ctrl.hint}</p>` : ""}`;
    } else if (ctrl.type === "select") {
      const opts = ctrl.options.map(o => `<option value="${o.value}">${escapeHtml(o.text)}</option>`).join("");
      wrap.innerHTML = `${label}
        <select id="ctrl-${ctrl.id}" class="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-slate-500 focus:outline-none">${opts}</select>`;
    }
    c.appendChild(wrap);
  }
}

function readControls(cfg) {
  const v = {};
  for (const ctrl of cfg.controls) v[ctrl.id] = $(`ctrl-${ctrl.id}`).value;
  return v;
}

async function runAttack(mode) {
  const cfg = ATTACKS[currentId];
  if (!cfg) return;
  const values = readControls(cfg);
  setResultLoading();
  try {
    const result = await cfg.run(mode, values);
    showResult(mode, result);
  } catch (e) {
    showResult(mode, { request: "(greška)", status: 0, body: { error: String(e) } });
  }
}

function setResultLoading() {
  $("resultBox").classList.remove("hidden");
  $("resultResponse").textContent = "učitavanje...";
  $("resultRequest").textContent = "";
  $("resultExplain").textContent = "";
}

function showResult(mode, result) {
  const box = $("resultBox");
  box.classList.remove("hidden");
  const header = $("resultHeader");
  const isSecure = mode === "secure";
  const blocked = result.status === 403 || result.status === 400 || result.body?.blocked;

  header.className = "px-6 py-3 font-semibold text-white " + (isSecure ? "bg-emerald-600" : "bg-red-600");
  header.textContent = `${isSecure ? "BEZBEDNA" : "RANJIVA"} grana  •  HTTP ${result.status}`;

  $("resultRequest").textContent = result.request;
  $("resultResponse").textContent = JSON.stringify(result.body, null, 2);

  const explain = $("resultExplain");
  if (isSecure && blocked) {
    explain.className = "text-sm text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-lg p-3";
    explain.innerHTML = "✅ <b>Napad je zaustavljen.</b> Bezbedna grana je prepoznala i blokirala zlonameran ulaz.";
  } else if (!isSecure) {
    explain.className = "text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg p-3";
    explain.innerHTML = "⚠️ <b>Napad je prošao.</b> Ranjiva grana nema zaštitu, pogledaj poruku u odgovoru.";
    const url = result.body?.url;
    if (url) explain.innerHTML += ` &nbsp; <a href="${url}" target="_blank" class="underline font-semibold">Otvori sačuvani fajl →</a>`;
  } else {
    explain.className = "text-sm text-slate-600 bg-slate-50 border border-slate-200 rounded-lg p-3";
    explain.innerHTML = "ℹ️ Normalan (bezopasan) zahtev je obrađen uspešno.";
  }
}

function selectAttack(id) {
  currentId = id;
  const cfg = ATTACKS[id];
  const meta = META[id];
  $("panel").classList.toggle("hidden", !cfg);
  $("resultBox").classList.add("hidden");
  if (!cfg || !meta) return;
  $("attackTitle").textContent = meta.title;
  $("attackCategory").textContent = meta.category;
  $("attackIntro").innerHTML = cfg.intro;
  $("attackSummary").textContent = meta.summary;
  renderControls(cfg);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

let META = {};

async function init() {
  const res = await fetch("/api/attacks");
  const list = await res.json();
  const sel = $("attackSelect");
  sel.innerHTML = `<option value="">izaberi napad...</option>`;
  for (const m of list) {
    META[m.id] = m;
    const opt = document.createElement("option");
    opt.value = m.id;
    opt.textContent = `${m.number}. ${m.title}`;
    if (!ATTACKS[m.id]) opt.textContent += "  (uskoro)";
    opt.disabled = !ATTACKS[m.id];
    sel.appendChild(opt);
  }
  sel.addEventListener("change", () => selectAttack(sel.value));
  $("runVulnerable").addEventListener("click", () => runAttack("vulnerable"));
  $("runSecure").addEventListener("click", () => runAttack("secure"));
}

init();
