// @ts-check
// Creating and changing a secret. The form never loads an existing password or note: to
// change one, the user types or generates a new value; left empty, it stays as it is.
// A connection (SSH, RDP) is stored and shown; the application opens no session (ADR 0067).
// A TOTP is set from the otpauth:// address or the base32 key the site gives, sent to the core,
// which keeps it sealed and computes the codes; the form never loads it back (ADR 0078).
// Web addresses and tags are loaded when the form opens on a secret; what the user changes in
// them goes to the core as elements to add and to remove, never as a whole new list (ADR 0082).

import { api } from "./api.js";
import { announce, byId, h, showError } from "./dom.js";

/** @typedef {import("./api.js").Entry} Entry */
/** @typedef {"password" | "note" | "ssh" | "rdp" | "ssh_key" | "totp"} FormKind */

const KINDS = /** @type {FormKind[]} */ (["password", "note", "ssh", "rdp", "ssh_key", "totp"]);

/**
 * Whether a typed TOTP looks like something the core may accept: an otpauth:// address, or at
 * least 16 base32 characters (10 bytes). The core decides; this only catches a slip early.
 * @param {string} text
 */
export function looksLikeTotp(text) {
  const t = text.trim();
  if (/^otpauth:\/\/totp\//i.test(t)) return true;
  const b32 = t.replace(/[\s=-]/g, "");
  return b32.length >= 16 && /^[A-Za-z2-7]+$/.test(b32);
}

const TOTP_HELP = "Collez l'adresse « otpauth://totp/… » ou la clé secrète en base32 (au moins 16 caractères) donnée par le site.";

/** @param {string} text One web address per line. */
const urlList = (text) => text.split("\n").map((u) => u.trim()).filter(Boolean);
/** @param {string} text Tags separated by commas. */
const tagList = (text) => text.split(",").map((t) => t.trim()).filter(Boolean);

/**
 * What to add and what to remove to turn `before` into `after`, each element once.
 * @param {string[]} before @param {string[]} after
 * @returns {{ add: string[], remove: string[] }}
 */
export function listChanges(before, after) {
  const add = [...new Set(after.filter((x) => !before.includes(x)))];
  const remove = [...new Set(before.filter((x) => !after.includes(x)))];
  return { add, remove };
}

/** Kind of the form that changes an entry of the list. @param {Entry | null} entry @returns {FormKind} */
function kindOf(entry) {
  if (entry?.kind === "note") return "note";
  if (entry?.kind === "ssh_connection") return "ssh";
  if (entry?.kind === "rdp_connection") return "rdp";
  if (entry?.kind === "totp") return "totp";
  return "password";
}

/** @param {import("./api.js").SecretRef} ref */
const linkValue = (ref) => `${ref.locker}:${ref.id}`;

/** @param {string} value @returns {import("./api.js").SecretRef | null} */
function linkOf(value) {
  const [locker, id] = value.split(":");
  return locker && id ? { locker, id } : null;
}

/**
 * @typedef {object} FormHooks
 * @property {(e: import("./api.js").ApiError) => boolean} onError  True when handled globally.
 * @property {(ref: import("./api.js").SecretRef | null) => void} onSaved
 */

export class SecretForm {
  /** @param {FormHooks} hooks */
  constructor(hooks) {
    this.hooks = hooks;
    this.dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-secret"));
    this.form = /** @type {HTMLFormElement} */ (byId("form-secret"));
    /** @type {Entry | null} */
    this.editing = null;
    this.title = /** @type {HTMLInputElement} */ (byId("secret-titre"));
    this.username = /** @type {HTMLInputElement} */ (byId("secret-identifiant"));
    this.password = /** @type {HTMLInputElement} */ (byId("secret-mdp"));
    this.urls = /** @type {HTMLTextAreaElement} */ (byId("secret-urls"));
    this.tags = /** @type {HTMLInputElement} */ (byId("secret-etiquettes"));
    this.notes = /** @type {HTMLTextAreaElement} */ (byId("secret-notes"));
    this.favorite = /** @type {HTMLInputElement} */ (byId("secret-favori"));
    this.locker = /** @type {HTMLSelectElement} */ (byId("secret-casier"));
    this.host = /** @type {HTMLInputElement} */ (byId("secret-hote"));
    this.port = /** @type {HTMLInputElement} */ (byId("secret-port"));
    this.domain = /** @type {HTMLInputElement} */ (byId("secret-domaine"));
    this.sshKey = /** @type {HTMLSelectElement} */ (byId("secret-cle"));
    this.jump = /** @type {HTMLSelectElement} */ (byId("secret-rebond"));
    this.hostKey = /** @type {HTMLInputElement} */ (byId("secret-empreinte"));
    this.passphrase = /** @type {HTMLInputElement} */ (byId("secret-phrase"));
    /** Ticked: the current password is cleared, not kept. */
    this.clearPassword = /** @type {HTMLInputElement} */ (byId("secret-mdp-effacer"));
    /** Ticked: the current notes are cleared, not kept. */
    this.clearNotes = /** @type {HTMLInputElement} */ (byId("secret-notes-effacer"));
    this.totp = /** @type {HTMLInputElement} */ (byId("secret-totp"));
    /** Ticked: the current TOTP is removed. */
    this.clearTotp = /** @type {HTMLInputElement} */ (byId("secret-totp-effacer"));
    /** @type {import("./api.js").ConnectionCard | null} Card of the connection being changed. */
    this.card = null;
    /** True once a private key file was chosen for this form. */
    this.keyChosen = false;
    /**
     * Web addresses and tags of the secret being changed, as loaded and as shown; null when
     * they could not be read (an older core): the form then hides them.
     * @type {{ urls: string[], tags: string[], urlsText: string, tagsText: string } | null}
     */
    this.sets = null;
    /** @type {{ id: string, name: string, personal: boolean }[]} Lockers a new secret may go to. */
    this.lockers = [];
    this.error = byId("secret-erreur");
    this.saving = false;

    this.form.addEventListener("submit", (e) => {
      e.preventDefault();
      void this.save();
    });
    this.form.addEventListener("change", (e) => {
      if (/** @type {HTMLElement} */ (e.target).getAttribute("name") === "secret-type") this.syncType();
    });
    for (const b of this.form.querySelectorAll("[data-fermer]")) {
      b.addEventListener("click", () => this.dialog.close());
    }
    this.dialog.addEventListener("close", () => this.clear());
    const show = byId("secret-mdp-voir");
    show.addEventListener("click", () => {
      const visible = this.password.type === "text";
      this.password.type = visible ? "password" : "text";
      show.textContent = visible ? "Afficher" : "Masquer";
      show.setAttribute("aria-pressed", visible ? "false" : "true");
    });
    byId("secret-mdp-generer").addEventListener("click", () => void this.generate());
    // An empty input keeps the current value: clearing it takes an explicit choice.
    for (const [box, input] of /** @type {[HTMLInputElement, HTMLInputElement | HTMLTextAreaElement][]} */ ([
      [this.clearPassword, this.password],
      [this.clearNotes, this.notes],
      [this.clearTotp, this.totp],
    ])) {
      box.addEventListener("change", () => {
        if (box.checked) input.value = "";
        input.disabled = box.checked;
      });
    }
    byId("secret-fichier-choisir").addEventListener("click", () => void this.chooseKey());
  }

  /**
   * Lockers a new secret may be created in: the personal one, and the shared ones where the
   * member writes.
   * @param {{ id: string, name: string, personal: boolean }[]} lockers
   */
  setLockers(lockers) {
    this.lockers = lockers;
  }

  /** @returns {FormKind} */
  kind() {
    const checked = /** @type {HTMLInputElement | null} */ (
      this.form.querySelector('input[name="secret-type"]:checked')
    );
    return KINDS.find((k) => k === checked?.value) ?? "password";
  }

  /** Shows the fields of the chosen type: `data-pour` lists the types a field belongs to. */
  syncType() {
    const kind = this.kind();
    for (const el of this.form.querySelectorAll("[data-pour], [data-creation], [data-ensembles]")) {
      const kinds = el.getAttribute("data-pour");
      const foreign = kinds !== null && !kinds.split(" ").includes(kind);
      // `data-creation`: only for a new secret; `data-ensembles`: web addresses and tags,
      // shown on a secret being changed only when the core could read them.
      const unavailable = !!this.editing
        && (el.hasAttribute("data-creation") || (el.hasAttribute("data-ensembles") && !this.sets));
      /** @type {HTMLElement} */ (el).hidden = foreign || unavailable;
    }
    // A choice of locker only when there is one to make.
    byId("secret-casier-champ").hidden = !!this.editing || this.lockers.length < 2;
    this.port.placeholder = kind === "rdp" ? "3389" : "22";
  }

  /**
   * Fills the choices of an SSH key and of a jump host with the live secrets of the vault.
   * A link the connection already carries stays in the list even when its target is gone.
   * @returns {Promise<boolean>} False when the list could not be read (the error is reported).
   */
  async loadLinks() {
    /** @type {Entry[]} */
    let entries;
    try {
      entries = (await api.list("", false)).entries;
    } catch (e) {
      this.hooks.onError(/** @type {import("./api.js").ApiError} */ (e));
      return false;
    }
    const self = this.editing?.id;
    /** @param {HTMLSelectElement} select @param {string} none @param {string} kind @param {import("./api.js").ResolvedLink | null} current */
    const fill = (select, none, kind, current) => {
      const options = [h("option", { value: "", text: none })];
      for (const e of entries) {
        if (e.kind !== kind || e.id === self) continue;
        const where = e.kind === "ssh_connection" && e.hosts[0] ? ` · ${e.username ? `${e.username}@` : ""}${e.hosts[0]}` : "";
        options.push(h("option", { value: linkValue(e), text: `${e.title}${where}` }));
      }
      if (current && !options.some((o) => o.getAttribute("value") === linkValue(current))) {
        options.push(h("option", { value: linkValue(current), text: current.title ?? "Lien actuel (cible introuvable)" }));
      }
      select.replaceChildren(...options);
      select.value = current ? linkValue(current) : "";
    };
    fill(this.sshKey, "Aucune", "ssh_key", this.card?.ssh_key ?? null);
    fill(this.jump, "Aucun (connexion directe)", "ssh_connection", this.card?.jumps[0] ?? null);
    return true;
  }

  /**
   * @param {Entry | null} entry  null: a new secret.
   * @param {string | null} [locker]  Locker proposed for a new secret.
   */
  async open(entry, locker = null) {
    this.clear();
    this.editing = entry;
    if (entry && ["ssh", "rdp"].includes(kindOf(entry))) {
      try {
        this.card = await api.connectionCard({ locker: entry.locker, id: entry.id });
      } catch (e) {
        const err = /** @type {import("./api.js").ApiError} */ (e);
        if (!this.hooks.onError(err)) announce(err.message, 6000);
        return;
      }
    }
    /** @type {Set<string> | null} Fields the secret holds, as far as the core tells. */
    let present = null;
    if (this.card) {
      present = new Set();
      if (this.card.has_password) present.add("password");
      if (this.card.has_notes) present.add("notes");
    } else if (entry) {
      try {
        const versions = await api.history({ locker: entry.locker, id: entry.id });
        if (versions.length) present = new Set(versions[0].fields);
      } catch {
        // Unknown: no clearing offered, an empty input keeps the value as before.
      }
    }
    if (entry) {
      try {
        const sets = await api.secretSets({ locker: entry.locker, id: entry.id });
        const urlsText = sets.urls.join("\n");
        const tagsText = sets.tags.join(", ");
        this.sets = { urls: sets.urls, tags: sets.tags, urlsText, tagsText };
        this.urls.value = urlsText;
        this.tags.value = tagsText;
      } catch {
        // An older core: addresses and tags stay as they are, and are not shown.
        this.sets = null;
      }
    }
    if (!(await this.loadLinks())) return;
    this.locker.replaceChildren(
      ...this.lockers.map((l) =>
        h("option", { value: l.id, text: l.personal ? `${l.name} (personnel)` : `${l.name} (partagé)` }),
      ),
    );
    if (locker && this.lockers.some((l) => l.id === locker)) this.locker.value = locker;
    byId("dialogue-secret-titre").textContent = entry ? "Modifier le secret" : "Nouveau secret";
    byId("secret-type-groupe").hidden = !!entry;
    byId("secret-mdp-aide").hidden = !entry;
    byId("secret-notes-aide").hidden = !entry;
    byId("secret-totp-aide").hidden = !entry || !present?.has("totp");
    const kind = kindOf(entry);
    for (const r of this.form.querySelectorAll('input[name="secret-type"]')) {
      /** @type {HTMLInputElement} */ (r).checked = /** @type {HTMLInputElement} */ (r).value === kind;
    }
    if (entry) {
      this.title.value = entry.title;
      this.username.value = entry.username ?? "";
      this.favorite.checked = entry.favorite;
    }
    if (this.card) {
      this.host.value = this.card.host ?? "";
      this.port.value = this.card.port === null ? "" : String(this.card.port);
      this.username.value = this.card.username ?? "";
      this.domain.value = this.card.domain ?? "";
      this.hostKey.value = this.card.host_key ?? "";
    }
    this.syncType();
    // Clearing is offered only for a field the secret holds; the content of a note stays.
    byId("secret-mdp-effacer-case").hidden = !present?.has("password");
    byId("secret-notes-effacer-case").hidden = kind === "note" || !present?.has("notes");
    byId("secret-totp-effacer-case").hidden = !present?.has("totp");
    this.dialog.showModal();
    this.title.focus();
  }

  /** Empties every input, so that no typed secret stays in the page. */
  clear() {
    for (const el of [
      this.title, this.username, this.password, this.urls, this.tags, this.notes,
      this.host, this.port, this.domain, this.hostKey, this.passphrase, this.totp,
    ]) {
      el.value = "";
    }
    this.card = null;
    this.keyChosen = false;
    this.sets = null;
    for (const box of [this.clearPassword, this.clearNotes, this.clearTotp]) box.checked = false;
    this.password.disabled = false;
    this.notes.disabled = false;
    this.totp.disabled = false;
    byId("secret-mdp-effacer-case").hidden = true;
    byId("secret-notes-effacer-case").hidden = true;
    byId("secret-totp-effacer-case").hidden = true;
    byId("secret-totp-aide").hidden = true;
    const file = byId("secret-fichier-nom");
    file.textContent = "Aucun fichier choisi";
    file.classList.remove("choisi");
    this.password.type = "password";
    byId("secret-mdp-voir").textContent = "Afficher";
    byId("secret-mdp-voir").setAttribute("aria-pressed", "false");
    this.favorite.checked = false;
    showError(this.error, null);
  }

  async generate() {
    try {
      this.password.value = await api.generate({ length: 24, lower: true, upper: true, digits: true, symbols: true });
      announce("Mot de passe généré.");
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (!this.hooks.onError(err)) showError(this.error, err.message);
    }
  }

  /** Asks the application for a private key file: the page only learns its name. */
  async chooseKey() {
    showError(this.error, null);
    try {
      const name = await api.chooseSshKeyFile();
      const file = byId("secret-fichier-nom");
      file.textContent = name;
      file.classList.add("choisi");
      this.keyChosen = true;
      if (!this.title.value) this.title.value = name;
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (err.code === "cancelled") return;
      if (!this.hooks.onError(err)) showError(this.error, err.message);
    }
  }

  /**
   * The port typed: null when empty.
   * @returns {number | null | undefined} undefined: not a port (the error is shown).
   */
  typedPort() {
    const text = this.port.value.trim();
    if (!text) return null;
    const n = /^[0-9]{1,5}$/.test(text) ? Number(text) : 0;
    if (n < 1 || n > 65535) {
      showError(this.error, "Le port est un nombre de 1 à 65535.");
      this.port.focus();
      return undefined;
    }
    return n;
  }

  /**
   * What to send for a connection: the fields to set and, when changing one, those to clear.
   * @param {FormKind} kind
   * @param {string} title
   * @returns {{ set: import("./api.js").ConnectionFields, clear: import("./api.js").ConnectionClear[] } | null}
   *   null: an input is refused (the error is shown).
   */
  connectionChanges(kind, title) {
    const host = this.host.value.trim();
    if (!host) {
      showError(this.error, "L'hôte est obligatoire.");
      this.host.focus();
      return null;
    }
    const port = this.typedPort();
    if (port === undefined) return null;
    const c = this.card;
    /** @type {import("./api.js").ConnectionFields} */
    const set = {};
    /** @type {import("./api.js").ConnectionClear[]} */
    const clear = [];
    /** @param {"username" | "domain" | "host_key"} key @param {string} value */
    const text = (key, value) => {
      if (value === ((c && c[key]) ?? "")) return;
      if (value) set[key] = value;
      else clear.push(key);
    };
    /** @param {"ssh_key" | "jump"} key @param {string} value @param {import("./api.js").ResolvedLink | null} current */
    const link = (key, value, current) => {
      if (value === (current ? linkValue(current) : "")) return;
      const ref = linkOf(value);
      if (ref) set[key] = ref;
      else clear.push(key);
    };
    if (title !== (c?.title ?? "")) set.title = title;
    if (host !== (c?.host ?? "")) set.host = host;
    if (port !== (c?.port ?? null)) {
      if (port === null) clear.push("port");
      else set.port = port;
    }
    text("username", this.username.value.trim());
    if (kind === "rdp") text("domain", this.domain.value.trim());
    text("host_key", this.hostKey.value.trim());
    if (kind === "ssh") link("ssh_key", this.sshKey.value, c?.ssh_key ?? null);
    link("jump", this.jump.value, c?.jumps[0] ?? null);
    if (this.clearPassword.checked) clear.push("password");
    else if (this.password.value) set.password = this.password.value;
    if (this.clearNotes.checked) clear.push("notes");
    else if (this.notes.value) set.notes = this.notes.value;
    if (this.favorite.checked !== (c?.favorite ?? false)) set.favorite = this.favorite.checked;
    return { set, clear };
  }

  /**
   * Web addresses and tags to add and remove on the secret being changed. An input left as it
   * was loaded changes nothing, even when splitting it again would not give the same list.
   * @returns {Record<string, string[]>}
   */
  setChanges() {
    /** @type {Record<string, string[]>} */
    const out = {};
    const s = this.sets;
    if (!s) return out;
    const put = (/** @type {string} */ name, /** @type {{ add: string[], remove: string[] }} */ c) => {
      if (c.add.length) out[`add_${name}`] = c.add;
      if (c.remove.length) out[`remove_${name}`] = c.remove;
    };
    const kind = this.kind();
    if ((kind === "password" || kind === "totp") && this.urls.value !== s.urlsText) {
      put("urls", listChanges(s.urls, urlList(this.urls.value)));
    }
    if (this.tags.value !== s.tagsText) put("tags", listChanges(s.tags, tagList(this.tags.value)));
    return out;
  }

  async save() {
    if (this.saving) return;
    const title = this.title.value.trim();
    if (!title) {
      showError(this.error, "Le titre est obligatoire.");
      this.title.focus();
      return;
    }
    const kindNow = this.kind();
    const typedTotp = (kindNow === "password" || kindNow === "totp") && !this.clearTotp.checked ? this.totp.value : "";
    if (kindNow === "totp" && !this.editing && !typedTotp.trim()) {
      showError(this.error, TOTP_HELP);
      this.totp.focus();
      return;
    }
    if (typedTotp.trim() && !looksLikeTotp(typedTotp)) {
      showError(this.error, TOTP_HELP);
      this.totp.focus();
      return;
    }
    this.saving = true;
    byId("secret-enregistrer").setAttribute("disabled", "");
    try {
      let ref = null;
      const kind = this.kind();
      const tags = () => tagList(this.tags.value);
      const target = this.lockers.find((l) => l.id === this.locker.value);
      const locker = target && !target.personal ? target.id : null;
      if (kind === "ssh" || kind === "rdp") {
        const changes = this.connectionChanges(kind, title);
        if (!changes) return;
        const e = this.editing;
        if (e) {
          const sets = this.setChanges();
          const fieldsChanged = Object.keys(changes.set).length > 0 || changes.clear.length > 0;
          if (!fieldsChanged && Object.keys(sets).length === 0) {
            this.dialog.close();
            return;
          }
          ref = { locker: e.locker, id: e.id };
          if (fieldsChanged) await api.updateConnection(ref, changes.set, changes.clear);
          if (Object.keys(sets).length) await api.update(ref, sets);
          announce("Connexion modifiée.");
        } else {
          ref = await api.createConnection({ kind, locker, fields: changes.set, tags: tags() });
          announce("Connexion créée.");
        }
      } else if (kind === "ssh_key") {
        if (!this.keyChosen) {
          showError(this.error, "Choisissez le fichier de la clé privée.");
          byId("secret-fichier-choisir").focus();
          return;
        }
        /** @type {{ locker: string | null, title: string, passphrase?: string, username?: string, tags: string[] }} */
        const key = { locker, title, tags: tags() };
        if (this.passphrase.value) key.passphrase = this.passphrase.value;
        if (this.username.value.trim()) key.username = this.username.value.trim();
        ref = await api.createSshKey(key);
        announce("Clé SSH rangée dans le coffre.");
      } else if (kind === "totp" && !this.editing) {
        /** @type {{ locker: string | null, title: string, input: string, username?: string, tags: string[] }} */
        const totp = { locker, title, input: typedTotp, tags: tags() };
        if (this.username.value.trim()) totp.username = this.username.value.trim();
        ref = await api.totpCreate(totp);
        // Notes and favourite are written next, as on any secret.
        /** @type {Record<string, unknown>} */
        const rest = {};
        if (this.notes.value) rest.notes = this.notes.value;
        if (this.favorite.checked) rest.favorite = true;
        const urls = urlList(this.urls.value);
        if (urls.length) rest.add_urls = [...new Set(urls)];
        if (Object.keys(rest).length) await api.update(ref, rest);
        announce("Code TOTP rangé dans le coffre.");
      } else if (this.editing) {
        /** @type {Record<string, unknown>} */
        const changes = {};
        /** @type {string[]} */
        const clear = [];
        const e = this.editing;
        const target = { locker: e.locker, id: e.id };
        // The TOTP first: it is the change most likely to be refused, and nothing else is
        // written when it is.
        let totpChanged = false;
        if (this.clearTotp.checked) {
          await api.totpClear(target);
          totpChanged = true;
        } else if (typedTotp.trim()) {
          await api.totpSet(target, typedTotp);
          totpChanged = true;
        }
        if (title !== e.title) changes.title = title;
        if (e.kind === "password" || e.kind === "totp") {
          const u = this.username.value;
          if (u !== (e.username ?? "")) {
            if (u) changes.username = u;
            else clear.push("username");
          }
        }
        if (e.kind === "password") {
          if (this.clearPassword.checked) clear.push("password");
          else if (this.password.value) changes.password = this.password.value;
        }
        if (this.clearNotes.checked) clear.push("notes");
        else if (this.notes.value) changes.notes = this.notes.value;
        if (this.favorite.checked !== e.favorite) changes.favorite = this.favorite.checked;
        if (clear.length) changes.clear = clear;
        Object.assign(changes, this.setChanges());
        if (Object.keys(changes).length === 0 && !totpChanged) {
          this.dialog.close();
          return;
        }
        if (Object.keys(changes).length) await api.update(target, changes);
        ref = target;
        announce("Secret modifié.");
      } else {
        /** @type {Record<string, unknown>} */
        const secret = {
          kind,
          locker,
          title,
          notes: this.notes.value || null,
          tags: tags(),
          favorite: this.favorite.checked,
        };
        if (kind === "password") {
          secret.username = this.username.value || null;
          secret.password = this.password.value || null;
          secret.urls = urlList(this.urls.value);
        }
        ref = await api.create(secret);
        if (typedTotp.trim()) {
          try {
            await api.totpSet(ref, typedTotp);
          } catch (e) {
            // The secret exists: say what was not stored, and let the user fix it from its record.
            const err = /** @type {import("./api.js").ApiError} */ (e);
            this.dialog.close();
            this.hooks.onSaved(ref);
            announce(`Secret créé, sans TOTP. ${err.message}`, 8000);
            return;
          }
        }
        announce("Secret créé.");
      }
      this.dialog.close();
      this.hooks.onSaved(ref);
    } catch (e) {
      const err = /** @type {import("./api.js").ApiError} */ (e);
      if (this.hooks.onError(err)) this.dialog.close();
      else showError(this.error, err.message);
    } finally {
      this.saving = false;
      byId("secret-enregistrer").removeAttribute("disabled");
    }
  }
}
