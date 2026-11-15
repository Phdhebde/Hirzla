// Fake Tauri bridge for screenshots and interface checks in a plain browser: it answers
// the application's commands with made-up data. Never shipped: it lives outside ui/ and is
// injected only by scripts/captures.mjs. No real secret here.
(() => {
  const cfg = window.__HIRZLA_MOCK__ || {};
  let state = cfg.state || "absent";
  const L = "6a1f0c2e9b8d4f17a3c5e0d2b4f6a8c1";
  const W = "0b3d5f7a9c1e2a4b6c8d0e2f4a6b8c0d";
  const id = (n) => n.toString(16).padStart(32, "0");
  const entries = [
    { locker: L, id: id(1), kind: "password", title: "Banque Populaire", username: "m.durand", hosts: ["banquepopulaire.fr"], tags: ["finances"], favorite: true, trash: false },
    { locker: L, id: id(2), kind: "password", title: "Messagerie Proton", username: "marie.durand@proton.me", hosts: ["account.proton.me"], tags: [], favorite: true, trash: false },
    { locker: L, id: id(3), kind: "note", title: "Codes de secours GitLab", username: null, hosts: [], tags: ["secours"], favorite: false, trash: false },
    { locker: L, id: id(4), kind: "password", title: "Impots.gouv.fr", username: "1 23 45 678 901 234", hosts: ["impots.gouv.fr"], tags: ["administration"], favorite: false, trash: false },
    { locker: W, id: id(5), kind: "password", title: "Routeur du bureau", username: "admin", hosts: ["192.168.1.1"], tags: ["réseau"], favorite: false, trash: false },
    { locker: W, id: id(6), kind: "ssh_key", title: "Serveur de sauvegarde", username: null, hosts: [], tags: ["infra"], favorite: false, trash: false },
    { locker: L, id: id(7), kind: "password", title: "Wi-Fi maison", username: null, hosts: [], tags: [], favorite: false, trash: false },
    { locker: L, id: id(8), kind: "password", title: "Ancien forum", username: "mdurand", hosts: ["forum.example"], tags: [], favorite: false, trash: true },
  ];
  const lockers = [
    { id: L, name: "Personnel", personal: true },
    { id: W, name: "Atelier", personal: false },
  ];
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
    app_hardening: { memory_locked: "failed", dumps_disabled: "applied", tracing_blocked: "applied" },
    app_version: "0.0.0",
  });
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
      return { entries: entries.filter((e) => (a.trash || !e.trash) && hit(e)), lockers };
    },
    reveal_field: (a) => {
      if (a.field === "notes" && a.target.id !== id(1) && a.target.id !== id(3)) return refuse("not_found", "Secret ou champ introuvable.");
      return values[a.field] || "";
    },
    copy_field: () => 30,
    create_secret: (a) => {
      const e = { locker: L, id: id(entries.length + 1), kind: a.secret.kind, title: a.secret.title, username: a.secret.username || null, hosts: [], tags: a.secret.tags || [], favorite: !!a.secret.favorite, trash: false };
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
