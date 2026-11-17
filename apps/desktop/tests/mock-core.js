// Fake Tauri bridge for screenshots and interface checks in a plain browser: it answers
// the application's commands with made-up data. Never shipped: it lives outside ui/ and is
// injected only by scripts/captures.mjs. No real secret here.
(() => {
  const cfg = window.__HIRZLA_MOCK__ || {};
  let state = cfg.state || "absent";
  const L = "6a1f0c2e9b8d4f17a3c5e0d2b4f6a8c1";
  const W = "0b3d5f7a9c1e2a4b6c8d0e2f4a6b8c0d";
  const id = (n) => n.toString(16).padStart(32, "0");
  const C = "c4a9e2f07d1b5c3e8a6f0b2d4e6a8c0f";
  const entries = [
    { locker: L, id: id(1), kind: "password", title: "Banque Populaire", username: "m.durand", hosts: ["banquepopulaire.fr"], tags: ["finances"], favorite: true, trash: false },
    { locker: L, id: id(2), kind: "password", title: "Messagerie Proton", username: "marie.durand@proton.me", hosts: ["account.proton.me"], tags: [], favorite: true, trash: false },
    { locker: L, id: id(3), kind: "note", title: "Codes de secours GitLab", username: null, hosts: [], tags: ["secours"], favorite: false, trash: false },
    { locker: L, id: id(4), kind: "password", title: "Impots.gouv.fr", username: "1 23 45 678 901 234", hosts: ["impots.gouv.fr"], tags: ["administration"], favorite: false, trash: false },
    { locker: L, id: id(5), kind: "password", title: "Routeur de la maison", username: "admin", hosts: ["192.168.1.1"], tags: ["réseau"], favorite: false, trash: false },
    { locker: W, id: id(6), kind: "ssh_key", title: "Serveur de sauvegarde", username: null, hosts: [], tags: ["infra"], favorite: false, trash: false },
    { locker: L, id: id(24), kind: "ssh_key", title: "Clé d'administration", username: "marie", hosts: [], tags: ["infra"], favorite: false, trash: false },
    { locker: L, id: id(21), kind: "ssh_connection", title: "Bastion de l'atelier", username: "marie", hosts: ["bastion.atelier-durand.fr"], tags: ["infra"], favorite: false, trash: false },
    { locker: L, id: id(22), kind: "ssh_connection", title: "Serveur de sauvegarde", username: "sauvegarde", hosts: ["10.20.0.14"], tags: ["infra"], favorite: true, trash: false },
    { locker: L, id: id(23), kind: "rdp_connection", title: "Poste de comptabilité", username: "m.durand", hosts: ["compta-01.atelier.lan"], tags: [], favorite: false, trash: false },
    { locker: L, id: id(25), kind: "totp", title: "Forge logicielle", username: "marie", hosts: [], tags: ["travail"], favorite: false, trash: false },
    { locker: L, id: id(7), kind: "password", title: "Wi-Fi maison", username: null, hosts: [], tags: [], favorite: false, trash: false },
    { locker: L, id: id(8), kind: "password", title: "Ancien forum", username: "mdurand", hosts: ["forum.example"], tags: [], favorite: false, trash: true },
    { locker: W, id: id(9), kind: "password", title: "Console du NAS", username: "atelier", hosts: ["nas.atelier.lan"], tags: ["infra"], favorite: false, trash: false },
    { locker: W, id: id(10), kind: "password", title: "Portail fournisseur", username: "commandes@atelier-durand.fr", hosts: ["pro.fournisseur.example"], tags: [], favorite: false, trash: false },
    { locker: C, id: id(11), kind: "password", title: "Banque — compte professionnel", username: "ATELIER-DURAND", hosts: ["entreprises.banque.example"], tags: ["finances"], favorite: false, trash: false },
    { locker: C, id: id(12), kind: "password", title: "Logiciel de paie", username: "m.durand", hosts: ["paie.example"], tags: [], favorite: false, trash: false },
  ];
  // Server mode: a joined server and its shared lockers (all made up). The captures change
  // this state through window.__HIRZLA_MOCK_SERVER__.
  const S = Object.assign(
    { joined: false, verified: false, synced: false, ca: false, lastSync: null, failSync: null, unreachable: false, suspect: false, alerts: [], lost: false, senior: false, quarantine: false, frozen: false, requests: [] },
    cfg.server || {},
  );
  window.__HIRZLA_MOCK_SERVER__ = S;
  const FP = "M7QKXR4PZD2VNBTL6WEA";
  const ME = "4be19c07a3d25f8e6b1c0d9e7f2a4b6c";
  const shared = [
    { id: W, name: "Atelier", role: "owner", unsent: 0, pending: 0, quarantined: 0 },
    { id: C, name: "Comptabilité", role: "reader", unsent: 0, pending: 0, quarantined: 0 },
  ];
  const others = {
    paul: "8d0f2a6c4e1b3d5f7a9c0e2b4d6f8a1c",
    lea: "2c7e9a1b3d5f0c8e6a4b2d0f9e7c5a3b",
    karim: "e5a3c1f9d7b5a3e1c9f7d5b3a1e9c7f5",
    claire: "a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0",
  };
  const FPS = {
    [ME]: "QH3VZK7N2RBXW5TMJ4DC",
    [others.paul]: "T4NWQ2ZK7HXB5RMD3VCJ",
    [others.lea]: "B6XJ3MQT7ZVN2KWR4PHD",
    [others.karim]: "R2HV7KQB4XZT6NMW3JDC",
    [others.claire]: "W5ZTD3KN7QXR2HVB6MJC",
  };
  // Display names (ADR 0069) and the fingerprints this user compared out of band.
  const NAMES = {
    [ME]: "Marie Durand",
    [others.paul]: "Paul Renaud",
    [others.lea]: "Léa Fontaine",
    [others.claire]: "Claire Martin",
  };
  const DIRECTORY = { "5e7a9c1b3d5f7a9c1b3d5f7a9c1b3d5f": ["Inès Leroy", "D7KQ2XZB5TVW3RMH6NJC"], "6f8b0d2c4e6a8c0e2a4c6e8a0c2e4a6c": ["Inès Lemaire", "H4RWQ6ZK2NXB7TMD5VCJ"] };
  for (const [m, [name, fp]] of Object.entries(DIRECTORY)) { NAMES[m] = name; FPS[m] = fp; }
  const compared = new Set([others.paul, others.claire]);
  let myName = "Marie Durand";
  const fpOf = (m) => FPS[m] || "N3KQ7XZB2TVW5RMH4DJC";
  const roster = {
    [W]: [
      { member: ME, role: "owner", devices: 2, proven: true },
      { member: others.paul, role: "manager", devices: 1, proven: true },
      { member: others.lea, role: "editor", devices: 1, proven: true },
      { member: others.karim, role: "reader", devices: 1, proven: false },
    ],
    [C]: [
      { member: others.claire, role: "owner", devices: 2, proven: true },
      { member: ME, role: "reader", devices: 2, proven: true },
      { member: others.paul, role: "editor", devices: 1, proven: true },
    ],
  };
  // Requests received through the server (ADR 0070), when the capture asks for mail.
  if (S.mail) {
    S.inbox = [{
      request: "7c2e9a4b1d6f3a8c5e0b2d4f6a8c0e1b", locker: C, name: "Comptabilité", action: "owner_removal",
      target: others.paul, target_fingerprint: fpOf(others.paul), target_name: NAMES[others.paul], target_verified: true,
      role: null, quorum: null, issuer: others.claire, issuer_fingerprint: fpOf(others.claire), issuer_name: NAMES[others.claire],
      issuer_verified: true, can_sign: true, required: 2, received_ms: Date.UTC(2026, 10, 16, 13, 5),
      offer: "hirzla-demande:pGEBYQKCUGofDC6bjU8Xo8XgLSL6jBQAx7Kq3mZp9TfR2wVbN4cHdL8sJ6gYkE1uQ0oA5iX",
    }];
    S.requests = [{
      request: "b83d5f1a9c7e2b4d6f8a0c2e4b6d8f0a", locker: W, action: "owner_role_change", target: others.claire, role: "manager", quorum: null,
      counted: [ME], required: 2, offer: "hirzla-demande:pGEBYQKCUHs9XyFanH4rTdbwoMLuS2AFy7Lq3nZq0UgS3xWcO5dIeM9tK7hZlF2vR1pB6jY",
      created_ms: Date.UTC(2026, 10, 15, 16, 28), sent_ms: Date.UTC(2026, 10, 15, 16, 30), declined: [], queued: 0,
    }];
  }
  const READERS = ["owner", "manager", "editor", "reader"];
  const ROLES = ["owner", "manager", "editor", "reader", "blind_user", "auditor"];
  const norm = (f) => (f || "").replace(/[\s-]/g, "").toUpperCase();
  // Governance (ADR 0044 to 0046): a senior owner in "Atelier", requests, quarantine.
  if (S.senior || S.mail) roster[W].unshift({ member: others.claire, role: "owner", devices: 1, proven: true });
  const OFFER = "hirzla-demande:pGEBYQKCUGofDC6bjU8Xo8XgLSL6jBQ" + "Ax7Kq3mZp9TfR2wVbN4cHdL8sJ6gYkE1uQ0oA5iX".repeat(3);
  const TOKEN = "hirzla-accord:pGEBYQJQah8MLpuNTxejxeAtIvqMFFBk" + "Vt3Hq9ZpL2xR7wNcB6mJ4dK8sY1gE5uA0oQ".repeat(4);
  const quarantined = () => (S.quarantine
    ? [
        { op_id: "3c9e".padEnd(96, "1"), member: others.karim, device: "1f2e3d4c5b6a79880716253443526170", cause: "removal", class: "data", wall_ms: Date.UTC(2026, 10, 14, 17, 5), title: "Console du NAS", secret: id(9), received_ms: Date.UTC(2026, 10, 15, 8, 2), due_ms: Date.UTC(2026, 10, 22, 8, 2) },
        { op_id: "a71b".padEnd(96, "2"), member: others.karim, device: "1f2e3d4c5b6a79880716253443526170", cause: "removal", class: "data", wall_ms: Date.UTC(2026, 10, 14, 17, 9), title: "Wi-Fi de l'atelier", secret: id(13), received_ms: Date.UTC(2026, 10, 15, 8, 2), due_ms: Date.UTC(2026, 10, 22, 8, 2) },
      ]
    : []);
  const lockerList = () => {
    const base = [{ id: L, name: "Personnel", personal: true }];
    if (S.joined && S.verified && S.synced) {
      for (const l of shared) base.push({ id: l.id, name: l.name, personal: false });
    }
    return base;
  };
  const membersOf = (locker) => {
    const list = roster[locker] || [];
    const mine = list.find((m) => m.member === ME);
    const lost = locker === C && S.lost;
    const owners = list.filter((m) => m.role === "owner").length;
    const owner = !!mine && mine.role === "owner";
    const manager = !!mine && mine.role === "manager";
    return {
      me: ME,
      grantable: lost ? [] : owner ? ROLES.slice() : manager ? ROLES.slice(2) : [],
      grant_refusal: lost ? "access_lost" : owner || manager ? null : "role",
      quorum: 2,
      members: list.map((m) => {
        const self = m.member === ME;
        let change_to = [];
        let change_refusal = null;
        let remove_refusal = null;
        if (lost) {
          change_refusal = "access_lost";
          remove_refusal = "access_lost";
        } else if (owner && m.member === others.claire && locker === W) {
          change_refusal = "quorum";
          remove_refusal = "quorum";
        } else if (owner) {
          if (self && owners === 1) {
            change_refusal = "last_owner";
            remove_refusal = "last_owner";
          } else {
            change_to = ROLES.filter((r) => r !== m.role && (!READERS.includes(m.role) || READERS.includes(r)));
          }
        } else {
          change_refusal = "role";
          remove_refusal = self ? null : "role";
        }
        return { member: m.member, me: self, role: m.role, devices: m.devices, fingerprint: fpOf(m.member), proven: m.proven, change_to, change_refusal, remove_refusal, name: self ? myName || null : NAMES[m.member] || null, verified: self || compared.has(m.member) };
      }),
    };
  };
  const SERVER_MSG = {
    fingerprint_mismatch: "Empreinte inattendue : elle ne correspond pas à la clé présentée. Rien n'a été enregistré ni envoyé. Vérifiez l'empreinte auprès de son détenteur par un autre canal ; si elle est exacte, quelqu'un s'interpose peut-être entre vous et le serveur.",
    server_unreachable: "Serveur injoignable, ou connexion sécurisée impossible. Vérifiez l'adresse et le réseau, puis réessayez. Vos secrets restent disponibles sur ce poste.",
    access_lost: "Accès perdu : le serveur ne vous sert plus ce casier. Demandez l'accès à son propriétaire.",
    keylog_rejected: "Registre des clés suspect : la clé de ce membre n'est pas prouvée par le registre de transparence, ou le serveur présente un registre incohérent. Le partage est suspendu. Prévenez votre administrateur de sécurité.",
    invalid: "Choisissez d'abord le certificat de l'autorité du site.",
    invitation_invalid: "Lien d'invitation non valide ou altéré. Demandez-le à nouveau à l'administrateur du serveur, ou saisissez l'adresse, l'autorité et l'empreinte séparément.",
    approval_invalid: "Accord refusé : texte altéré, signature fausse, signataire qui n'est pas propriétaire du casier, accord déjà compté ou destiné à une autre demande.",
  };
  const values = {
    password: "c7#Lq9vT!m2Rz@4wXe",
    notes: "Compte joint ouvert en 2019. Conseiller : agence de Lyon.",
    username: "m.durand",
    ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2fakeKeyForScreenshotsOnly hirzla",
    ssh_passphrase: "phrase de passe de démonstration",
  };
  const status = () => ({
    state,
    auto_lock_s: 300,
    clipboard_clear_s: 30,
    core_version: "0.0.0",
    core_hardening: { memory_locked: "failed", dumps_disabled: "applied", tracing_blocked: "applied" },
    app_hardening: { memory_locked: "not_attempted", dumps_disabled: "applied", tracing_blocked: "applied" },
    app_version: "0.0.0",
  });
  let local = { keep_in_tray: true, tray_available: true };
  /** @type {string[]} */
  let trusted = ["C:\\Program Files\\KeePassXC\\KeePassXC.exe"];
  let settings = { auto_lock_s: 300, clipboard_clear_s: 30, lock_on_sleep: true, lock_on_session_lock: true };
  let kit = cfg.kit === undefined ? { kit: "3fa2c901", threshold: 2, count: 3 } : cfg.kit;
  // Hardware unlock methods (ADR 0075): the master password, then those enrolled.
  const methods = [{ rank: 0, kind: "password", usable: true, needs_pin: false }, ...(cfg.methods || [])];
  const enrollable = cfg.enrollable || ["hello", "fido2"];
  /** @type {string | null} */
  let kdbxKey = null;
  const v = (n) => n.toString(16).padStart(96, "0");
  const history = [
    { version: v(3), wall_ms: Date.UTC(2026, 9, 2, 8, 14), state: "active", title: "Banque Populaire", username: "m.durand", fields: ["title", "notes", "username", "password"], changed: ["password"], custom: 0 },
    { version: v(2), wall_ms: Date.UTC(2026, 3, 18, 17, 2), state: "active", title: "Banque Populaire", username: "m.durand", fields: ["title", "notes", "username", "password"], changed: ["notes"], custom: 0 },
    { version: v(1), wall_ms: Date.UTC(2025, 11, 4, 10, 40), state: "active", title: "Banque Populaire", username: "m.durand", fields: ["title", "username", "password"], changed: ["title", "username", "password"], custom: 0 },
  ];
  // Cards of the connections (local API version 6): what the list does not carry.
  const jumpBastion = { locker: L, id: id(21), state: "valid", title: "Bastion de l'atelier", host: "bastion.atelier-durand.fr", port: 2222, username: "marie", public_key: null };
  const keyLink = { locker: L, id: id(24), state: "valid", title: "Clé d'administration", host: null, port: null, username: null, public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8mVh0kq2 sauvegarde@atelier" };
  const cards = {
    [id(21)]: { kind: "ssh", port: 2222, effective_port: 2222, domain: null, host_key: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", has_password: false, has_notes: true, ssh_key: keyLink, jumps: [] },
    [id(22)]: { kind: "ssh", port: null, effective_port: 22, domain: null, host_key: "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM", has_password: true, has_notes: false, ssh_key: keyLink, jumps: [jumpBastion] },
    [id(23)]: { kind: "rdp", port: null, effective_port: 3389, domain: "ATELIER", host_key: null, has_password: true, has_notes: false, ssh_key: null, jumps: [jumpBastion] },
  };
  // Fields each secret holds (what `secret_history` lists, never a value): only the bank
  // account, the tax account and the GitLab note have notes, only the backup server key has
  // a passphrase. `update_secret` changes them.
  const changedFields = new Map();
  const fieldsOf = (sid) => {
    if (changedFields.has(sid)) return changedFields.get(sid);
    const e = entries.find((x) => x.id === sid);
    if (!e) return [];
    const f = ["title"];
    if (e.username) f.push("username");
    if (e.kind === "password") f.push("password");
    if (e.kind === "ssh_key") f.push("ssh_public_key");
    if (sid === id(6)) f.push("ssh_passphrase");
    if (sid === id(1) || sid === id(3) || sid === id(4)) f.push("notes");
    // TOTP (ADR 0078): the mail account carries one, and the TOTP secret of the forge.
    if (sid === id(2) || e.kind === "totp") f.push("totp");
    return f;
  };
  const refuse = (code, message) => Promise.reject({ code, message, retry_after_s: null });
  const delay = (v) => new Promise((r) => setTimeout(() => r(v), 30));
  const handlers = {
    app_status: () => status(),
    create_vault: () => { state = "unlocked"; },
    unlock: (a) => {
      if (a.password !== "démonstration") return refuse("unlock_failed", "Déverrouillage refusé : mot de passe incorrect, ou coffre altéré.");
      state = "unlocked";
    },
    lock: () => { state = "locked"; },
    list_secrets: (a) => {
      if (state !== "unlocked") return refuse("locked", "Le coffre est verrouillé.");
      const q = (a.query || "").toLowerCase();
      const hit = (e) => !q || [e.title, e.username || "", ...e.hosts, ...e.tags].some((t) => t.toLowerCase().includes(q));
      const lockers = lockerList();
      const shown = (e) => lockers.some((l) => l.id === e.locker);
      return { entries: entries.filter((e) => shown(e) && (a.trash || !e.trash) && hit(e)), lockers };
    },
    reveal_field: (a) => {
      if (!fieldsOf(a.target.id).includes(a.field)) return refuse("not_found", "Secret ou champ introuvable.");
      return values[a.field] || "";
    },
    copy_field: () => 30,
    create_secret: (a) => {
      const e = { locker: a.secret.locker || L, id: id(entries.length + 1), kind: a.secret.kind, title: a.secret.title, username: a.secret.username || null, hosts: [], tags: a.secret.tags || [], favorite: !!a.secret.favorite, trash: false };
      entries.push(e);
      return { locker: e.locker, id: e.id };
    },
    update_secret: (a) => {
      const e = entries.find((x) => x.id === a.target.id);
      if (e && "favorite" in a.changes) e.favorite = a.changes.favorite;
      if (e && a.changes.title) e.title = a.changes.title;
      if (e) {
        const f = new Set(fieldsOf(e.id));
        for (const k of ["username", "password", "notes"]) if (a.changes[k]) f.add(k);
        for (const k of a.changes.clear || []) f.delete(k);
        changedFields.set(e.id, [...f]);
      }
    },
    delete_secret: (a) => {
      const i = entries.findIndex((x) => x.id === a.target.id);
      if (i >= 0) { if (a.purge) entries.splice(i, 1); else entries[i].trash = true; }
    },
    // TOTP codes (local API version 13): made-up codes, never a TOTP secret.
    totp_code: (a) => {
      if (state !== "unlocked") return refuse("locked", "Le coffre est verrouillé.");
      if (!fieldsOf(a.target.id).includes("totp")) return refuse("not_found", "Secret ou champ introuvable.");
      const forge = a.target.id === id(25);
      return { code: forge ? "40917253" : "287082", seconds_left: 18, period: 30, digits: forge ? 8 : 6, algorithm: forge ? "SHA-256" : "SHA-1", issuer: forge ? "Forge" : "Proton" };
    },
    totp_copy: (a) => (fieldsOf(a.target.id).includes("totp") ? 30 : refuse("not_found", "Secret ou champ introuvable.")),
    totp_set: (a) => {
      if (!/^otpauth:\/\/totp\//i.test(a.input.trim()) && !/^[A-Za-z2-7\s=-]{16,}$/.test(a.input.trim())) {
        return refuse("invalid", "TOTP refusé : collez l'adresse otpauth://totp/… donnée par le site (souvent sous le QR code), ou sa clé secrète en base32 (au moins 16 caractères). Ni HOTP, ni code Steam.");
      }
      changedFields.set(a.target.id, [...new Set([...fieldsOf(a.target.id), "totp"])]);
    },
    totp_clear: (a) => {
      changedFields.set(a.target.id, fieldsOf(a.target.id).filter((f) => f !== "totp"));
    },
    totp_create: (a) => {
      const e = { locker: a.totp.locker || L, id: id(entries.length + 30), kind: "totp", title: a.totp.title, username: a.totp.username || null, hosts: [], tags: a.totp.tags || [], favorite: false, trash: false };
      entries.push(e);
      return { locker: e.locker, id: e.id };
    },
    connection_card: (a) => {
      const e = entries.find((x) => x.id === a.target.id);
      if (!e || !cards[e.id]) return refuse("not_found", "Secret ou champ introuvable.");
      return { ...cards[e.id], trashed: e.trash, title: e.title, host: e.hosts[0], username: e.username, favorite: e.favorite, tags: e.tags };
    },
    create_connection: (a) => {
      const f = a.connection.fields;
      const kind = a.connection.kind;
      const e = { locker: a.connection.locker || L, id: id(entries.length + 40), kind: `${kind}_connection`, title: f.title, username: f.username || null, hosts: [f.host], tags: a.connection.tags || [], favorite: !!f.favorite, trash: false };
      entries.push(e);
      const target = (ref) => entries.find((x) => ref && x.id === ref.id);
      const key = target(f.ssh_key);
      const jump = target(f.jump);
      cards[e.id] = {
        kind, port: f.port ?? null, effective_port: f.port ?? (kind === "rdp" ? 3389 : 22), domain: f.domain || null,
        host_key: f.host_key || null, has_password: !!f.password, has_notes: !!f.notes,
        ssh_key: key ? { locker: key.locker, id: key.id, state: "valid", title: key.title, host: null, port: null, username: null, public_key: null } : null,
        jumps: jump ? [{ locker: jump.locker, id: jump.id, state: "valid", title: jump.title, host: jump.hosts[0], port: cards[jump.id]?.effective_port ?? 22, username: jump.username, public_key: null }, ...(cards[jump.id]?.jumps ?? [])] : [],
      };
      return { locker: e.locker, id: e.id };
    },
    update_connection: (a) => {
      const e = entries.find((x) => x.id === a.target.id);
      const c = e && cards[e.id];
      if (!e || !c) return refuse("not_found", "Secret ou champ introuvable.");
      if (a.set.title) e.title = a.set.title;
      if (a.set.host) e.hosts = [a.set.host];
      if (a.set.username) e.username = a.set.username;
      if ("favorite" in a.set) e.favorite = a.set.favorite;
      if (a.set.port) { c.port = a.set.port; c.effective_port = a.set.port; }
      if (a.set.host_key) c.host_key = a.set.host_key;
      if (a.set.password) c.has_password = true;
      if (a.set.notes) c.has_notes = true;
      for (const k of a.clear) {
        if (k === "port") { c.port = null; c.effective_port = c.kind === "rdp" ? 3389 : 22; }
        if (k === "username") e.username = null;
        if (k === "host_key") c.host_key = null;
        if (k === "ssh_key") c.ssh_key = null;
        if (k === "jump") c.jumps = [];
        if (k === "password") c.has_password = false;
        if (k === "notes") c.has_notes = false;
      }
    },
    choose_ssh_key_file: () => "id_ed25519",
    create_ssh_key: (a) => {
      const e = { locker: a.key.locker || L, id: id(entries.length + 40), kind: "ssh_key", title: a.key.title, username: a.key.username || null, hosts: [], tags: a.key.tags || [], favorite: false, trash: false };
      entries.push(e);
      return { locker: e.locker, id: e.id };
    },
    generate_password: () => "Vn4%tB8qZ!e2Lr6#Wm9sKd3x",
    copy_generated: () => 30,
    generator_profiles: () => {
      const base = { mode: "characters", lower: true, upper: true, digits: true, symbols: true, excluded: "",
        no_ambiguous: false, same_keys: false, no_repeat: false, start_letter: false };
      return [
        { id: "defaut", target_bits: 128, spec: { ...base, length: 24, minimums: [2, 2, 2, 2], symbol_set: "!#$%&*+-=?@^_", no_ambiguous: true, no_repeat: true, start_letter: true } },
        { id: "longue-duree", target_bits: 256, spec: { ...base, length: 40, minimums: [1, 1, 1, 1], symbol_set: null } },
        { id: "site-capricieux", target_bits: 80, spec: { ...base, length: 16, minimums: [1, 1, 1, 1], symbol_set: "-_!", no_repeat: true, start_letter: true } },
        { id: "wifi", target_bits: 80, spec: { ...base, length: 20, symbols: false, minimums: [1, 1, 1, 0], symbol_set: null, no_ambiguous: true } },
        { id: "compte-de-service", target_bits: 128, spec: { ...base, length: 32, minimums: [1, 1, 1, 1], symbol_set: "-_.+=^~", no_repeat: true } },
      ];
    },
    generate_with: (a) => {
      const samples = {
        characters: ["v7#Kq2m!Rz9@Lp4&Xt6$Wn8%", "Hb3?tN8=wQ5@yC2!mV7#zK4+", "r9^Gd2&Lx6!Ps3@Fj8$Tn5*W", "Mq4!vB7#cZ2@hK9$xD5&gR3=",
          "t6@Yw3!Nf8#Lc2$Hp7&Jm4^Q", "Xz5#kG2!bV9@nT4$rW7&dS3?", "j8$Pm3@Qx6!Fc2#Lh9&Tv4=B", "Dn7!wK4#zR2@gY9$cM5&xH3+",
          "p3@Vt8!Lq6#Bn2$Fz7&Kd4^W", "Gh9#rC2!mX5@jT8$wN4&Pv3="],
        passphrase: ["cuivre-lanterne-9-orage-velours-matin"],
        pronounceable: ["Tovirudak-menlosiba-kunefalo-37"],
        pin: ["804157"],
        template: ["Kd-4821-mqz-TR"],
      };
      const bits = { characters: a.spec.length * 6.13, passphrase: 81.4, pronounceable: 66.2, pin: 19.6, template: 64.1 };
      const pool = { characters: 70, passphrase: 7776, pronounceable: 80, pin: 10, template: 0 };
      if (a.spec.mode === "characters" && !(a.spec.lower || a.spec.upper || a.spec.digits || a.spec.symbols)) {
        return refuse("invalid", "Ces réglages sont refusés : ils sont hors limites, se contredisent, ou leurs règles écartent presque tous les tirages.");
      }
      const list = samples[a.spec.mode];
      return {
        values: Array.from({ length: a.count }, (_, i) => list[i % list.length]),
        strength: { entropy_millibits: Math.floor(bits[a.spec.mode] * 1000), pool: pool[a.spec.mode] },
      };
    },
    copy_generated_at: () => 30,
    import_csv: () => ({ imported: 42, empty: 1, refused_lines: [17], totp_skipped: 2 }),
    auto_type_available: () => true,
    auto_type_prepare: () => ({
      typed: false,
      target: {
        name: "mstsc.exe",
        path: "C:\\Windows\\System32\\mstsc.exe",
        title: "Connexion Bureau à distance",
        terminal: false,
        can_remember: true,
      },
    }),
    auto_type_confirm: (a) => {
      if (a.remember && !trusted.includes("C:\\Windows\\System32\\mstsc.exe")) trusted.push("C:\\Windows\\System32\\mstsc.exe");
    },
    auto_type_cancel: () => {},
    auto_type_trusted: () => [...trusted],
    auto_type_forget: (a) => {
      trusted = a.path === null ? [] : trusted.filter((p) => p !== a.path);
      return [...trusted];
    },
    get_preferences: () => ({ ...local }),
    set_preferences: (a) => {
      local = { ...local, keep_in_tray: a.keep_in_tray };
      return { ...local };
    },
    get_settings: () => ({ ...settings }),
    set_settings: (a) => {
      const s = a.settings;
      if ((s.auto_lock_s !== 0 && (s.auto_lock_s < 30 || s.auto_lock_s > 86400)) || s.clipboard_clear_s < 5 || s.clipboard_clear_s > 600) {
        return refuse("invalid", "Le verrouillage automatique doit être compris entre 30 s et 24 h.");
      }
      settings = { ...s };
    },
    change_password: (a) => {
      if (a.current !== "démonstration") return refuse("unlock_failed", "Déverrouillage refusé : mot de passe incorrect, ou coffre altéré.");
    },
    restore_secret: (a) => {
      const e = entries.find((x) => x.id === a.target.id);
      if (e) e.trash = false;
    },
    secret_history: (a) => {
      if (a.target.id === id(1)) return history.map((x, i) => (i === 0 ? { ...x, fields: fieldsOf(id(1)) } : x));
      const e = entries.find((x) => x.id === a.target.id);
      if (!e) return refuse("not_found", "Secret ou champ introuvable.");
      return [{ version: v(1), wall_ms: Date.UTC(2026, 0, 12, 9, 30), state: e.trash ? "trash" : "active", title: e.title, username: e.username, fields: fieldsOf(e.id), changed: fieldsOf(e.id), custom: 0 }];
    },
    reveal_version: (a) => (a.field === "password" ? "ancien-Mot-de-passe-2025" : "Ancienne note."),
    copy_version: () => 30,
    restore_version: () => {},
    recovery_status: () => kit,
    create_recovery_kit: (a) => {
      kit = { kit: "7be04d1a", threshold: a.threshold, count: a.count };
      const files = Array.from({ length: a.count }, (_, i) => `hirzla-part-7be04d1a-${i + 1}.hirzla-part`);
      return { ...kit, folder: "/home/marie/Documents/recouvrement", files };
    },
    choose_recovery_shares: () => ["hirzla-part-3fa2c901-1.hirzla-part", "hirzla-part-3fa2c901-3.hirzla-part"],
    recovery_unlock: () => { state = "unlocked"; },
    remove_recovery_kit: () => { kit = null; },
    list_unlock_methods: () => ({ methods, enrollable }),
    enroll_unlock_method: (a) => {
      if (a.password !== "démonstration") return refuse("unlock_failed", "Refusé : mot de passe maître incorrect, réponse refusée par le matériel, ou coffre altéré.");
      const rank = methods.length;
      methods.push({ rank, kind: a.kind, usable: true, needs_pin: false });
      return delay(rank);
    },
    unlock_with_method: () => delay(undefined).then(() => { state = "unlocked"; }),
    remove_unlock_method: (a) => { methods.splice(a.rank, 1); },
    choose_kdbx_file: () => { kdbxKey = null; return "Personnel.kdbx"; },
    choose_kdbx_key_file: () => { kdbxKey = "Personnel.keyx"; return kdbxKey; },
    clear_kdbx_key_file: () => { kdbxKey = null; },
    import_kdbx: (a) => {
      const ok = kdbxKey ? a.password === "" || a.password === "keepass" : a.password === "keepass";
      if (!ok) return refuse("import", "Mot de passe ou fichier clé de la base KeePass incorrect, ou base altérée.");
      kdbxKey = null;
      return { imported: 57, empty: 2, recycled: 4, attachments: 1, history: 23, custom_skipped: 0, totp: 1, refused: 0 };
    },
    export_locker: (a) => {
      if (a.password !== null && a.password.length < 16) return refuse("export_password_weak", "Mot de passe trop faible : au moins 16 caractères, dont 8 différents.");
      const password = a.password === null ? "falaise-orage-brindille-tamis-lanterne-cobalt-vergue-osier" : null;
      return { password, file: "Atelier.hirzla-export", secrets: 3, trashed: 1, attachments: 0, links_dropped: 0 };
    },
    copy_export_password: () => 30,
    choose_export_file: () => "Equipe-reseau.hirzla-export",
    import_locker: (a) => {
      if (a.password !== "falaise-orage-brindille-tamis-lanterne-cobalt-vergue-osier") return refuse("export_key_rejected", "Mot de passe incorrect, ou fichier d'export altéré. Rien n'a été importé.");
      return { locker: "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b", secrets: 12, attachments: 1, folders_as_tags: 2, refused: 0 };
    },
    server_status: () => {
      if (!S.joined) return { joined: false, url: null, server_id: null, fingerprint: null, verified: false, last_sync_ms: null, keylog: null, lockers: [] };
      return {
        joined: true,
        url: "hirzla://coffre.atelier-durand.fr:7443",
        server_id: "5e0c7a91b3d24f68a0c1e2d3f4a5b6c7",
        fingerprint: FP,
        verified: S.verified,
        last_sync_ms: S.lastSync,
        keylog: { suspect: S.suspect, reason: S.suspect ? "shorter" : null, entries: 148, alerts: S.alerts },
        lockers: S.verified && S.synced
          ? shared.map((l) => ({
              ...l,
              access: !(l.id === C && S.lost),
              frozen: l.id === W && S.frozen,
              quarantined: l.id === W ? quarantined().length : l.quarantined,
            }))
          : [],
      };
    },
    server_identity: () => ({ member: ME, fingerprint: fpOf(ME), device: "9f3e1d7b5a2c4e6f8a0b1c2d3e4f5a6b", control_code: "K2PVQ7XN4MZ8R3TJ6WAB", name: myName || null }),
    export_server_identity: () => "hirzla-membre-4be19c07.hirzla-membre",
    choose_server_ca: () => {
      S.ca = true;
      return "ac-atelier-durand.pem";
    },
    server_join: (a) => {
      if (!S.ca) return refuse("invalid", SERVER_MSG.invalid);
      if (S.unreachable) return refuse("server_unreachable", SERVER_MSG.server_unreachable);
      if (a.fingerprint && norm(a.fingerprint) !== FP) return refuse("fingerprint_mismatch", SERVER_MSG.fingerprint_mismatch);
      S.joined = true;
      S.verified = !!a.fingerprint;
      S.ca = false;
      return { fingerprint: FP, verified: S.verified, account: true };
    },
    server_confirm: (a) => {
      if (norm(a.fingerprint) !== FP) return refuse("fingerprint_mismatch", SERVER_MSG.fingerprint_mismatch);
      S.verified = true;
      return true;
    },
    server_sync: () => {
      if (S.failSync) return refuse(S.failSync, SERVER_MSG[S.failSync]);
      S.synced = true;
      S.lastSync = Date.now();
      return shared.map((l, i) => ({ locker: l.id, received: i === 0 ? 3 : 1, sent: i === 0 ? 1 : 0, refused: 0, access: !(l.id === C && S.lost) }));
    },
    create_shared_locker: (a) => {
      if (S.suspect) return refuse("keylog_rejected", SERVER_MSG.keylog_rejected);
      const lid = id(0xabc000 + shared.length);
      shared.push({ id: lid, name: a.name, role: "owner", unsent: 0, pending: 0, quarantined: 0 });
      roster[lid] = [{ member: ME, role: "owner", devices: 2, proven: true }];
      return lid;
    },
    locker_members: (a) => membersOf(a.locker),
    grant_role: (a) => {
      if (S.suspect) return refuse("keylog_rejected", SERVER_MSG.keylog_rejected);
      const m = norm(a.member).toLowerCase();
      if (!/^[0-9a-f]{32}$/.test(m)) return refuse("invalid", "Identifiant du membre non valide : 32 chiffres hexadécimaux.");
      const list = roster[a.locker] || [];
      const got = list.find((x) => x.member === m);
      if (got) got.role = a.role;
      else list.push({ member: m, role: a.role, devices: 1, proven: true });
      return fpOf(m);
    },
    revoke_role: (a) => {
      const list = roster[a.locker] || [];
      const i = list.findIndex((x) => x.member === a.member);
      if (i >= 0) list.splice(i, 1);
    },
    revoke_device: (a) => {
      const i = S.alerts.findIndex((x) => x.kind === "unknown_device" && x.device === a.device);
      if (i < 0) return refuse("not_found", "Appareil introuvable sur ce poste. Synchronisez, puis réessayez.");
      S.alerts.splice(i, 1);
      return 1;
    },
    server_join_link: (a) => {
      const link = (a.link || "").replace(/\s/g, "");
      if (!link.startsWith("hirzla-invitation:") || link.includes("XX")) return refuse("invitation_invalid", SERVER_MSG.invitation_invalid);
      S.joined = true;
      S.verified = true;
      return { fingerprint: FP, verified: true, account: true };
    },
    quorum_prepare: (a) => {
      const q = {
        request: "d41f8a0c" + "2b6e9d13c57a0f4e".slice(0, 8) + "8b2c6e0a4d1f3b5c",
        locker: a.locker,
        action: a.action,
        target: a.target,
        role: a.role,
        quorum: a.quorum,
        counted: [ME],
        required: 2,
        offer: OFFER,
        created_ms: Date.UTC(2026, 10, 15, 14, 3),
        sent_ms: null,
        declined: [],
        queued: 0,
      };
      S.requests = [q];
      return q;
    },
    quorum_list: () => S.requests,
    quorum_inspect: (a) => {
      if (!(a.offer || "").startsWith("hirzla-demande:")) return refuse("approval_invalid", SERVER_MSG.approval_invalid);
      return { locker: W, name: "Atelier", action: "owner_removal", target: others.karim, target_fingerprint: fpOf(others.karim), role: null, quorum: null, issuer: others.paul, issuer_fingerprint: fpOf(others.paul), can_sign: true, target_name: NAMES[others.karim] || null, issuer_name: NAMES[others.paul] };
    },
    quorum_approve: () => TOKEN,
    quorum_collect: (a) => {
      if (!(a.token || "").startsWith("hirzla-accord:") || !S.requests.length) return refuse("approval_invalid", SERVER_MSG.approval_invalid);
      const q = S.requests[0];
      if (!q.counted.includes(others.lea)) q.counted.push(others.lea);
      return q;
    },
    profile_set: (a) => { myName = (a.name || "").trim(); },
    member_search: (a) => {
      const q = (a.text || "").trim().toLowerCase();
      if (q.length < 2) return refuse("invalid", "Saisissez au moins deux caractères du nom recherché.");
      if (S.unreachable) return refuse("server_unreachable", SERVER_MSG.server_unreachable);
      const members = Object.entries(NAMES)
        .filter(([m, name]) => m !== ME && name.toLowerCase().includes(q))
        .map(([member, name]) => ({ member, name, fingerprint: fpOf(member), verified: compared.has(member) }));
      return { members, more: false };
    },
    member_verify: (a) => {
      if (norm(a.fingerprint) !== fpOf(a.member)) return refuse("fingerprint_mismatch", SERVER_MSG.fingerprint_mismatch);
      compared.add(a.member);
    },
    quorum_send: (a) => {
      const q = S.requests.find((x) => x.request === a.request);
      if (!q) return refuse("not_found", "Demande introuvable sur ce poste.");
      if (S.unreachable) q.queued = 1;
      else { q.sent_ms = Date.UTC(2026, 10, 15, 14, 4); q.queued = 0; }
      return q;
    },
    quorum_inbox: () => S.inbox || [],
    quorum_respond: (a) => {
      S.inbox = (S.inbox || []).filter((r) => r.request !== a.request);
      return a.accept ? TOKEN : null;
    },
    quorum_apply: () => { S.requests = []; },
    quorum_cancel: () => { S.requests = []; },
    quarantine_list: () => ({ ops: quarantined(), can_decide: true }),
    quarantine_decide: () => { S.quarantine = false; },
  };
  window.__TAURI__ = {
    core: {
      invoke: (cmd, args = {}) => {
        const h = handlers[cmd];
        if (!h) return refuse("internal", "Commande inconnue.");
        try {
          const r = h(args);
          return r instanceof Promise ? r : delay(r);
        } catch (e) {
          return Promise.reject(e);
        }
      },
    },
  };
})();
