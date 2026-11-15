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
  const READERS = ["owner", "manager", "editor", "reader"];
  const ROLES = ["owner", "manager", "editor", "reader", "blind_user", "auditor"];
  const norm = (f) => (f || "").replace(/[\s-]/g, "").toUpperCase();
  // Governance (ADR 0044 to 0046): a senior owner in "Atelier", requests, quarantine.
  if (S.senior) roster[W].unshift({ member: others.claire, role: "owner", devices: 1, proven: true });
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
        return { member: m.member, me: self, role: m.role, devices: m.devices, fingerprint: fpOf(m.member), proven: m.proven, change_to, change_refusal, remove_refusal };
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
  let settings = { auto_lock_s: 300, clipboard_clear_s: 30, lock_on_sleep: true, lock_on_session_lock: true };
  let kit = cfg.kit === undefined ? { kit: "3fa2c901", threshold: 2, count: 3 } : cfg.kit;
  const v = (n) => n.toString(16).padStart(96, "0");
  const history = [
    { version: v(3), wall_ms: Date.UTC(2026, 9, 2, 8, 14), state: "active", title: "Banque Populaire", username: "m.durand", fields: ["title", "notes", "username", "password"], changed: ["password"], custom: 0 },
    { version: v(2), wall_ms: Date.UTC(2026, 3, 18, 17, 2), state: "active", title: "Banque Populaire", username: "m.durand", fields: ["title", "notes", "username", "password"], changed: ["notes"], custom: 0 },
    { version: v(1), wall_ms: Date.UTC(2025, 11, 4, 10, 40), state: "active", title: "Banque Populaire", username: "m.durand", fields: ["title", "username", "password"], changed: ["title", "username", "password"], custom: 0 },
  ];
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
      if (a.field === "notes" && a.target.id !== id(1) && a.target.id !== id(3)) return refuse("not_found", "Secret ou champ introuvable.");
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
    },
    delete_secret: (a) => {
      const i = entries.findIndex((x) => x.id === a.target.id);
      if (i >= 0) { if (a.purge) entries.splice(i, 1); else entries[i].trash = true; }
    },
    generate_password: () => "Vn4%tB8qZ!e2Lr6#Wm9sKd3x",
    copy_generated: () => 30,
    import_csv: () => ({ imported: 42, empty: 1, refused_lines: [17], totp_skipped: 2 }),
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
    secret_history: () => history,
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
    choose_kdbx_file: () => "Personnel.kdbx",
    import_kdbx: (a) => {
      if (a.password !== "keepass") return refuse("import", "Mot de passe de la base KeePass incorrect, ou base altérée.");
      return { imported: 57, empty: 2, recycled: 4, attachments: 1, history: 23, custom_skipped: 0, totp: 1, refused: 0 };
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
    server_identity: () => ({ member: ME, fingerprint: fpOf(ME), device: "9f3e1d7b5a2c4e6f8a0b1c2d3e4f5a6b", control_code: "K2PVQ7XN4MZ8R3TJ6WAB" }),
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
      };
      S.requests = [q];
      return q;
    },
    quorum_list: () => S.requests,
    quorum_inspect: (a) => {
      if (!(a.offer || "").startsWith("hirzla-demande:")) return refuse("approval_invalid", SERVER_MSG.approval_invalid);
      return { locker: W, name: "Atelier", action: "owner_removal", target: others.karim, target_fingerprint: fpOf(others.karim), role: null, quorum: null, issuer: others.paul, issuer_fingerprint: fpOf(others.paul), can_sign: true };
    },
    quorum_approve: () => TOKEN,
    quorum_collect: (a) => {
      if (!(a.token || "").startsWith("hirzla-accord:") || !S.requests.length) return refuse("approval_invalid", SERVER_MSG.approval_invalid);
      const q = S.requests[0];
      if (!q.counted.includes(others.lea)) q.counted.push(others.lea);
      return q;
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
