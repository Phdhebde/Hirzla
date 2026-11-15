// @ts-check
// Server mode (local API version 4, ADR 0032 and 0041): joining a server, confirming its
// fingerprint, synchronising, shared lockers, members and roles, and the state of the key
// transparency log. The core does every network exchange; this page only shows what it
// answers and sends what the user typed.

import { api } from "./api.js";
import { announce, byId, h, showError } from "./dom.js";
import { confirmDialog } from "./vault.js";

/** @typedef {import("./api.js").ApiError} ApiError */
/** @typedef {import("./api.js").ServerStatus} ServerStatus */
/** @typedef {import("./api.js").SharedLocker} SharedLocker */
/** @typedef {import("./api.js").RoleName} RoleName */
/** @typedef {import("./api.js").Refusal} Refusal */
/** @typedef {import("./api.js").Member} Member */

/** Role names, in the order of `roles.md`. */
export const ROLE_NAMES = /** @type {Record<RoleName, string>} */ ({
  owner: "Propriétaire",
  manager: "Gestionnaire",
  editor: "Éditeur",
  reader: "Lecteur",
  blind_user: "Utilisateur sans divulgation",
  auditor: "Auditeur",
});

/** Roles that may write secrets in a shared locker. */
export const WRITING_ROLES = /** @type {RoleName[]} */ (["owner", "manager", "editor"]);

const ACCESS_LOST = "Accès perdu : le serveur ne vous sert plus ce casier. Demandez l'accès à son propriétaire.";

/** Why a control is disabled, by action (`docs/api-locale.md` § 15.2, refusal codes). */
const REFUSALS = /** @type {Record<"grant" | "change" | "remove", Record<Refusal, string>>} */ ({
  grant: {
    role: "Seuls les propriétaires et les gestionnaires ajoutent des membres.",
    quorum: "Cette action exige l'accord de plusieurs propriétaires.",
    last_owner: "Cette action est réservée à un propriétaire.",
    access_lost: ACCESS_LOST,
  },
  change: {
    role: "Seul un propriétaire change les rôles.",
    quorum: "Ce propriétaire est plus ancien que vous : changer son rôle exige l'accord de plusieurs propriétaires, que cette version ne recueille pas encore.",
    last_owner: "Le dernier propriétaire ne peut pas être rétrogradé. Nommez d'abord un autre propriétaire.",
    access_lost: ACCESS_LOST,
  },
  remove: {
    role: "Seul un propriétaire retire un autre membre.",
    quorum: "Ce propriétaire est plus ancien que vous : le retirer exige l'accord de plusieurs propriétaires, que cette version ne recueille pas encore.",
    last_owner: "Le dernier propriétaire ne peut pas quitter le casier. Nommez d'abord un autre propriétaire.",
    access_lost: ACCESS_LOST,
  },
});

const SUSPECT_REASONS = /** @type {Record<string, string>} */ ({
  root: "la racine recalculée diffère de celle que le serveur a signée",
  shorter: "le serveur présente un registre plus court qu'un registre déjà vérifié (restauration d'une ancienne sauvegarde, ou histoire réécrite)",
  rule: "une entrée enfreint les règles du registre",
  peer: "la tête du registre vue par un autre poste ne correspond pas à celle de ce poste",
  proof: "une preuve d'inscription contredit le registre de ce poste",
});

/** @param {import("./api.js").KeyLogAlert} a */
function alertText(a) {
  const device = a.device ? ` (poste ${a.device.slice(0, 8)}…)` : "";
  if (a.kind === "foreign_member_key") {
    return ["Clé de membre usurpée", `Une clé qui n'est pas la vôtre est inscrite à votre nom (entrée ${a.index}).`];
  }
  if (a.kind === "unknown_device") {
    return [
      "Appareil inconnu inscrit à votre nom",
      `Un appareil que vous n'avez pas enrôlé est inscrit à votre nom${device}, entrée ${a.index}. Prévenez votre administrateur de sécurité.`,
    ];
  }
  return ["Révocation inconnue", `Une révocation que vous n'avez pas faite est inscrite à votre nom${device}, entrée ${a.index}.`];
}

/**
 * A fingerprint in groups of five characters, easier to compare aloud.
 * @param {string | null | undefined} fp
 */
export function grouped(fp) {
  return (fp ?? "").replace(/(.{5})(?=.)/g, "$1 ");
}

/** @param {number} ms */
function when(ms) {
  const d = new Date(ms);
  const today = new Date().toDateString() === d.toDateString();
  return today
    ? `aujourd'hui à ${d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}`
    : d.toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" });
}

/** @param {number} n @param {string} one @param {string} many */
function count(n, one, many) {
  return `${n} ${n > 1 ? many : one}`;
}

/**
 * @param {HTMLElement} el
 * @param {"scelle" | "ouvert" | "alerte" | "neutre"} kind
 * @param {"carre" | "rond" | "triangle"} shape
 * @param {string} text
 */
function setState(el, kind, shape, text) {
  el.className = `${el.className.replace(/\betat-(scelle|ouvert|alerte|neutre)\b/g, "").trim()} etat-${kind}`;
  if (!el.classList.contains("etat")) el.classList.add("etat");
  el.replaceChildren(h("span", { class: `forme forme-${shape}`, "aria-hidden": "true" }), text);
}

/**
 * @typedef {object} ServerHooks
 * @property {(e: ApiError) => boolean} onError  True when handled globally (locked vault, lost core).
 * @property {() => Promise<void>} onChanged  The lockers may have changed: refresh the list.
 * @property {(status: ServerStatus | null) => void} onStatus  New state of the server mode.
 * @property {() => void} onShow  Show the server view.
 */

export class ServerView {
  /** @param {ServerHooks} hooks */
  constructor(hooks) {
    this.hooks = hooks;
    /** @type {ServerStatus | null} */
    this.status = null;
    /** @type {ApiError | null} Refusal of the last synchronisation, kept until the next one. */
    this.syncError = null;
    this.syncing = false;
    this.members = new MembersDialog(hooks, () => void this.refresh());
    this.lockerDialog = new LockerDialog(hooks, async (id) => {
      await this.refresh();
      await this.hooks.onChanged();
      return id;
    });

    byId("form-rejoindre").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.join();
    });
    byId("rejoindre-ac").addEventListener("click", () => void this.chooseCa());
    byId("form-confirmer").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.confirm();
    });
    for (const id of ["connexion-synchroniser", "bouton-synchroniser"]) {
      byId(id).addEventListener("click", () => void this.sync());
    }
    for (const id of ["etat-serveur", "bandeau-voir"]) {
      byId(id).addEventListener("click", () => this.hooks.onShow());
    }
    byId("identite-exporter").addEventListener("click", () => void this.exportIdentity());
    for (const id of ["casiers-nouveau", "bouton-casier-partage"]) {
      byId(id).addEventListener("click", () => this.lockerDialog.open());
    }
  }

  /** @param {string} id @returns {SharedLocker | undefined} */
  locker(id) {
    return this.status?.lockers.find((l) => l.id === id);
  }

  /** Forgets everything shown: called when the vault locks. */
  wipe() {
    this.status = null;
    this.syncError = null;
    this.members.wipe();
    for (const id of ["identite-membre", "identite-empreinte", "identite-poste", "identite-code", "rejoindre-ac-nom"]) {
      byId(id).textContent = "";
    }
    for (const id of ["rejoindre-adresse", "rejoindre-empreinte", "confirmer-saisie"]) {
      /** @type {HTMLInputElement} */ (byId(id)).value = "";
    }
    for (const id of ["rejoindre-erreur", "confirmer-erreur", "connexion-erreur"]) showError(byId(id), null);
    byId("connexion-resultat").hidden = true;
    for (const id of ["casiers-lignes", "registre-alertes", "confirmer-empreinte", "confirmer-adresse"]) {
      byId(id).replaceChildren();
    }
    this.render();
  }

  /** Reads the state of the server mode from the core and shows it. */
  async refresh() {
    try {
      this.status = await api.serverStatus();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) announce(err.message, 6000);
      return;
    }
    this.render();
    this.hooks.onStatus(this.status);
  }

  async loadIdentity() {
    try {
      const id = await api.serverIdentity();
      byId("identite-membre").textContent = id.member;
      byId("identite-empreinte").textContent = grouped(id.fingerprint);
      byId("identite-poste").textContent = id.device;
      byId("identite-code").textContent = grouped(id.control_code);
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) announce(err.message, 6000);
    }
  }

  render() {
    const s = this.status;
    const joined = !!s?.joined;
    const verified = joined && !!s?.verified;
    byId("serveur-rejoindre").hidden = !s || joined;
    byId("serveur-confirmer").hidden = !joined || verified;
    for (const id of ["serveur-connexion", "serveur-registre", "serveur-casiers"]) byId(id).hidden = !verified;
    byId("bouton-synchroniser").hidden = !verified;
    byId("bouton-casier-partage").hidden = !verified;
    /** @type {HTMLButtonElement} */ (byId("bouton-synchroniser")).disabled = this.syncing;
    /** @type {HTMLButtonElement} */ (byId("connexion-synchroniser")).disabled = this.syncing;
    this.renderPill();
    this.renderBanner();
    if (!s || !joined) return;
    byId("confirmer-empreinte").textContent = grouped(s.fingerprint);
    byId("confirmer-adresse").textContent = `Serveur ${s.url} · identifiant ${s.server_id}`;
    if (!verified) return;

    // Connection.
    const state = byId("connexion-etat");
    if (this.syncing) setState(state, "neutre", "rond", "Synchronisation en cours…");
    else if (this.syncError) setState(state, "alerte", "triangle", this.syncErrorTitle());
    else if (s.last_sync_ms) setState(state, "scelle", "carre", "Synchronisé");
    else setState(state, "neutre", "rond", "Pas encore synchronisé depuis l'ouverture du coffre");
    byId("connexion-adresse").textContent = s.url ?? "";
    byId("connexion-empreinte").textContent = `${grouped(s.fingerprint)} · vérifiée`;
    byId("connexion-synchro").textContent = s.last_sync_ms ? when(s.last_sync_ms) : "aucune depuis l'ouverture du coffre";
    showError(byId("connexion-erreur"), this.syncError?.message ?? null);

    // Key log.
    const k = s.keylog;
    const reg = byId("registre-etat");
    if (k?.suspect) {
      setState(reg, "alerte", "triangle", "Registre suspect : partage suspendu");
      byId("registre-detail").textContent =
        `Le serveur présente un registre des clés incohérent : ${SUSPECT_REASONS[k.reason ?? ""] ?? "preuve d'incohérence"}. ` +
        "Vos casiers restent lisibles et modifiables, mais le noyau refuse toute nouvelle attribution de rôle et tout " +
        "nouveau casier partagé. Prévenez votre administrateur de sécurité ; le registre ne redevient pas sain tout seul.";
    } else {
      setState(reg, "scelle", "carre", "Registre cohérent");
      byId("registre-detail").textContent = k
        ? `${count(k.entries, "entrée vérifiée", "entrées vérifiées")} sur ce poste.`
        : "";
    }
    byId("registre-alertes").replaceChildren(
      ...(k?.alerts ?? []).map((a) => {
        const [title, text] = alertText(a);
        return h("li", { class: "alerte" }, [
          h("p", { class: "alerte-titre" }, [h("span", { class: "forme forme-triangle", "aria-hidden": "true" }), title]),
          h("p", { text }),
        ]);
      }),
    );

    // Shared lockers.
    byId("casiers-vide").hidden = s.lockers.length > 0;
    byId("casiers-lignes").replaceChildren(...s.lockers.map((l) => this.lockerRow(l)));
  }

  /** @param {SharedLocker} l */
  lockerRow(l) {
    /** @type {string[]} */
    const notes = [];
    if (l.unsent) notes.push(`${count(l.unsent, "modification", "modifications")} à envoyer`);
    if (l.pending) notes.push(`${l.pending} en attente`);
    if (l.quarantined) notes.push(`${l.quarantined} en quarantaine`);
    const state = l.access
      ? h("span", { text: notes.length ? notes.join(", ") : "À jour" })
      : h("span", { class: "etat etat-alerte" }, [h("span", { class: "forme forme-triangle", "aria-hidden": "true" }), "Accès perdu"]);
    const members = /** @type {HTMLButtonElement} */ (
      h("button", { class: "bouton bouton-secondaire bouton-petit", type: "button", text: "Membres" })
    );
    const name = l.name ?? "Casier sans nom lisible";
    members.setAttribute("aria-label", `Membres de ${name}`);
    members.addEventListener("click", () => void this.members.open(l.id, name));
    return h("tr", {}, [
      h("td", {}, [h("span", { text: name }), h("span", { class: "refus mono", text: l.id.slice(0, 8) })]),
      h("td", { text: l.role ? ROLE_NAMES[l.role] : "Aucun rôle" }),
      h("td", {}, [state]),
      h("td", {}, [members]),
    ]);
  }

  syncErrorTitle() {
    const code = this.syncError?.code;
    if (code === "server_unreachable") return "Serveur injoignable";
    if (code === "access_lost") return "Accès perdu";
    if (code === "keylog_rejected") return "Registre des clés suspect";
    if (code === "server_refused") return "Refusé par le serveur";
    return "Synchronisation impossible";
  }

  /** The state of the connection in the header. */
  renderPill() {
    const pill = byId("etat-serveur");
    const s = this.status;
    pill.hidden = !s?.joined;
    if (!s?.joined) return;
    if (!s.verified) setState(pill, "alerte", "triangle", "Empreinte à confirmer");
    else if (this.syncing) setState(pill, "neutre", "rond", "Synchronisation…");
    else if (this.syncError) setState(pill, "alerte", "triangle", this.syncErrorTitle());
    else if (s.last_sync_ms) {
      const t = new Date(s.last_sync_ms).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
      setState(pill, "neutre", "rond", `Synchronisé à ${t}`);
    } else setState(pill, "neutre", "rond", "Pas encore synchronisé");
  }

  /** The alert strip of the open vault: the most serious server mode problem, if any. */
  renderBanner() {
    const s = this.status;
    let title = "";
    let detail = "";
    const lost = s?.lockers.filter((l) => !l.access) ?? [];
    if (s?.keylog?.suspect) {
      title = "Registre des clés suspect : le partage est suspendu.";
      detail = "Le serveur présente un registre des clés incohérent. Prévenez votre administrateur de sécurité.";
    } else if (s?.keylog && s.keylog.alerts.length > 0) {
      const [t] = alertText(s.keylog.alerts[0]);
      title = `${t}.`;
      detail =
        s.keylog.alerts.length > 1
          ? `${count(s.keylog.alerts.length, "alerte", "alertes")} sur vos clés. Prévenez votre administrateur de sécurité.`
          : "Prévenez votre administrateur de sécurité.";
    } else if (lost.length > 0) {
      const names = lost.map((l) => `« ${l.name ?? l.id.slice(0, 8)} »`).join(", ");
      title = lost.length > 1 ? "Accès perdu à plusieurs casiers." : "Accès perdu à un casier.";
      detail = `Le serveur ne vous sert plus ${names}. Demandez l'accès à son propriétaire.`;
    } else if (s?.joined && !s.verified) {
      title = "Empreinte du serveur à confirmer.";
      detail = "Rien n'est synchronisé avant que vous l'ayez comparée avec celle de l'administrateur.";
    }
    byId("bandeau-serveur").hidden = !title;
    byId("bandeau-titre").textContent = title;
    byId("bandeau-detail").textContent = detail;
  }

  async chooseCa() {
    const error = byId("rejoindre-erreur");
    showError(error, null);
    try {
      byId("rejoindre-ac-nom").textContent = await api.chooseServerCa();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (err.code !== "cancelled" && !this.hooks.onError(err)) showError(error, err.message);
    }
  }

  async join() {
    const address = /** @type {HTMLInputElement} */ (byId("rejoindre-adresse"));
    const fp = /** @type {HTMLInputElement} */ (byId("rejoindre-empreinte"));
    const error = byId("rejoindre-erreur");
    const button = /** @type {HTMLButtonElement} */ (byId("rejoindre-envoyer"));
    if (!address.value.trim()) {
      showError(error, "Saisissez l'adresse du serveur.");
      address.focus();
      return;
    }
    if (!byId("rejoindre-ac-nom").textContent) {
      showError(error, "Choisissez d'abord le certificat de l'autorité du site.");
      byId("rejoindre-ac").focus();
      return;
    }
    showError(error, null);
    button.disabled = true;
    button.textContent = "Connexion au serveur…";
    try {
      const r = await api.serverJoin(address.value, fp.value.trim() || null);
      address.value = "";
      fp.value = "";
      byId("rejoindre-ac-nom").textContent = "";
      if (r.verified) {
        announce(
          r.account
            ? "Serveur rattaché, empreinte vérifiée. Le serveur reconnaît votre compte."
            : "Serveur rattaché, empreinte vérifiée. Le serveur ne connaît pas encore votre compte : transmettez votre identité à l'administrateur.",
          8000,
        );
      } else {
        announce("Serveur enregistré. Comparez maintenant son empreinte avec celle de l'administrateur.", 6000);
      }
      await this.refresh();
      byId(r.verified ? "connexion-synchroniser" : "confirmer-saisie").focus();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) showError(error, err.message);
    } finally {
      button.disabled = false;
      button.textContent = "Rejoindre le serveur";
    }
  }

  async confirm() {
    const input = /** @type {HTMLInputElement} */ (byId("confirmer-saisie"));
    const error = byId("confirmer-erreur");
    if (!input.value.trim()) {
      showError(error, "Recopiez l'empreinte que l'administrateur vous a transmise.");
      input.focus();
      return;
    }
    showError(error, null);
    try {
      const account = await api.serverConfirm(input.value);
      input.value = "";
      announce(
        account
          ? "Empreinte confirmée. Le serveur reconnaît votre compte."
          : "Empreinte confirmée. Le serveur ne connaît pas encore votre compte : transmettez votre identité à l'administrateur, puis synchronisez.",
        8000,
      );
      await this.refresh();
      byId("connexion-synchroniser").focus();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) showError(error, err.message);
    }
  }

  async sync() {
    if (this.syncing) return;
    this.syncing = true;
    byId("connexion-resultat").hidden = true;
    this.render();
    try {
      const reports = await api.serverSync();
      this.syncError = null;
      const received = reports.reduce((n, r) => n + r.received, 0);
      const sent = reports.reduce((n, r) => n + r.sent, 0);
      const refused = reports.reduce((n, r) => n + r.refused, 0);
      let text = `Synchronisé : ${count(received, "modification reçue", "modifications reçues")}, ${count(sent, "envoyée", "envoyées")}.`;
      if (refused) text += ` ${count(refused, "modification refusée", "modifications refusées")} par le serveur.`;
      if (reports.some((r) => !r.access)) text += " Le serveur vous a retiré l'accès à un casier.";
      const box = byId("connexion-resultat");
      box.textContent = text;
      box.hidden = false;
      announce(text);
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) return;
      this.syncError = err;
    } finally {
      this.syncing = false;
    }
    await this.refresh();
    await this.hooks.onChanged();
  }

  async exportIdentity() {
    try {
      const name = await api.exportServerIdentity();
      announce(`Clé publique de membre enregistrée dans ${name}. Transmettez ce fichier à l'administrateur.`, 6000);
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (err.code !== "cancelled" && !this.hooks.onError(err)) announce(err.message, 6000);
    }
  }
}

/** Creation of a shared locker. */
class LockerDialog {
  /**
   * @param {ServerHooks} hooks
   * @param {(id: string) => Promise<string>} onCreated
   */
  constructor(hooks, onCreated) {
    this.hooks = hooks;
    this.onCreated = onCreated;
    this.dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-casier"));
    this.name = /** @type {HTMLInputElement} */ (byId("casier-nom"));
    byId("form-casier").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.create();
    });
    this.dialog.addEventListener("close", () => {
      this.name.value = "";
      showError(byId("casier-erreur"), null);
    });
  }

  open() {
    this.name.value = "";
    showError(byId("casier-erreur"), null);
    this.dialog.showModal();
    this.name.focus();
  }

  async create() {
    const error = byId("casier-erreur");
    const name = this.name.value.trim();
    if (!name) {
      showError(error, "Donnez un nom au casier.");
      this.name.focus();
      return;
    }
    const button = /** @type {HTMLButtonElement} */ (byId("casier-creer"));
    button.disabled = true;
    button.textContent = "Création…";
    try {
      const id = await api.createSharedLocker(name);
      this.dialog.close();
      announce(`Casier partagé « ${name} » créé. Vous en êtes le propriétaire.`);
      await this.onCreated(id);
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) this.dialog.close();
      else showError(error, err.message);
    } finally {
      button.disabled = false;
      button.textContent = "Créer le casier";
    }
  }
}

/** Members and roles of a shared locker. Every control follows what the core allows. */
class MembersDialog {
  /**
   * @param {ServerHooks} hooks
   * @param {() => void} onChanged
   */
  constructor(hooks, onChanged) {
    this.hooks = hooks;
    this.onChanged = onChanged;
    this.dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-membres"));
    /** @type {string | null} */
    this.locker = null;
    this.name = "";
    this.busy = false;
    byId("ajout-envoyer").addEventListener("click", () => void this.add());
    this.dialog.addEventListener("close", () => this.wipe());
  }

  wipe() {
    this.locker = null;
    byId("membres-lignes").replaceChildren();
    for (const id of ["ajout-membre", "ajout-empreinte"]) /** @type {HTMLInputElement} */ (byId(id)).value = "";
    showError(byId("membres-erreur"), null);
  }

  /** @param {string} locker @param {string} name */
  async open(locker, name) {
    this.locker = locker;
    this.name = name;
    showError(byId("membres-erreur"), null);
    byId("membres-titre").textContent = `Membres de « ${name} »`;
    if (!(await this.load())) return;
    if (!this.dialog.open) this.dialog.showModal();
    const first = /** @type {HTMLElement | null} */ (this.dialog.querySelector("select:not(:disabled), input:not(:disabled), button:not(:disabled)"));
    first?.focus();
  }

  /** @returns {Promise<boolean>} */
  async load() {
    if (!this.locker) return false;
    let m;
    try {
      m = await api.lockerMembers(this.locker);
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) {
        if (this.dialog.open) showError(byId("membres-erreur"), err.message);
        else announce(err.message, 6000);
      }
      return false;
    }
    const me = m.members.find((x) => x.me);
    byId("membres-role").textContent = me
      ? `Votre rôle : ${ROLE_NAMES[me.role].toLowerCase()}. ${count(m.members.length, "membre", "membres")}.`
      : "Vous n'avez pas de rôle dans ce casier.";
    byId("membres-lignes").replaceChildren(...m.members.map((x) => this.row(x)));

    // Adding a member.
    const fieldset = /** @type {HTMLFieldSetElement} */ (byId("membres-ajout"));
    const select = /** @type {HTMLSelectElement} */ (byId("ajout-role"));
    select.replaceChildren(
      ...(m.grantable.length
        ? m.grantable.map((r) => h("option", { value: r, text: ROLE_NAMES[r] }))
        : [h("option", { value: "", text: "Aucun rôle attribuable" })]),
    );
    if (m.grantable.includes("reader")) select.value = "reader";
    fieldset.disabled = m.grantable.length === 0;
    const help = byId("ajout-aide");
    if (m.grant_refusal) {
      help.textContent = REFUSALS.grant[m.grant_refusal];
    } else {
      help.textContent =
        "Le noyau vérifie que la clé du membre est inscrite au registre de transparence ; l'empreinte, obtenue du " +
        "membre lui-même par un autre canal, ajoute une comparaison hors bande." +
        (m.grantable.includes("owner") ? "" : " Seul un propriétaire nomme un propriétaire ou un gestionnaire.");
    }
    return true;
  }

  /** @param {Member} x */
  row(x) {
    const id = h("span", { class: "mono", text: `${x.member.slice(0, 16)}…`, title: x.member });
    const who = h("td", {}, [
      id,
      x.me ? h("span", { class: "vous", text: " (vous)" }) : null,
      h("span", { class: "refus", text: count(x.devices, "poste", "postes") }),
    ]);

    /** @type {HTMLElement} */
    let role;
    if (x.change_to.length > 0) {
      const select = /** @type {HTMLSelectElement} */ (
        h("select", { class: "saisie" }, [
          h("option", { value: x.role, text: ROLE_NAMES[x.role], selected: true }),
          ...x.change_to.map((r) => h("option", { value: r, text: ROLE_NAMES[r] })),
        ])
      );
      select.setAttribute("aria-label", `Rôle de ${x.me ? "vous-même" : x.member.slice(0, 8)}`);
      select.addEventListener("change", () => void this.change(x, /** @type {RoleName} */ (select.value), select));
      const readerLimit = ["owner", "manager", "editor", "reader"].includes(x.role)
        ? h("span", { class: "refus", text: "Pour lui ôter la lecture : retirez-le, puis ajoutez-le de nouveau." })
        : null;
      role = h("td", {}, [select, readerLimit]);
    } else {
      role = h("td", {}, [
        h("span", { text: ROLE_NAMES[x.role] }),
        x.change_refusal ? h("span", { class: "refus", text: REFUSALS.change[x.change_refusal] }) : null,
      ]);
    }

    const fp = h("td", {}, [
      h("span", { class: "mono", text: grouped(x.fingerprint) }),
      x.proven ? null : h("span", { class: "preuve-absente", text: "Sans preuve d'inscription au registre" }),
    ]);

    const remove = /** @type {HTMLButtonElement} */ (
      h("button", {
        class: "bouton bouton-secondaire bouton-danger bouton-petit",
        type: "button",
        text: x.me ? "Quitter le casier" : "Retirer",
      })
    );
    remove.disabled = !!x.remove_refusal;
    const why = x.remove_refusal
      ? h("span", { class: "refus", id: `refus-retrait-${x.member}`, text: REFUSALS.remove[x.remove_refusal] })
      : null;
    if (why) remove.setAttribute("aria-describedby", `refus-retrait-${x.member}`);
    remove.addEventListener("click", () => void this.remove(x));
    return h("tr", {}, [who, role, fp, h("td", {}, [remove, why])]);
  }

  /**
   * @param {Member} x
   * @param {RoleName} to
   * @param {HTMLSelectElement} select
   */
  async change(x, to, select) {
    const ok = await confirmDialog(
      `Donner le rôle ${ROLE_NAMES[to].toLowerCase()} ?`,
      `${x.me ? "Vous passerez" : `Le membre ${x.member.slice(0, 8)}… passera`} de ${ROLE_NAMES[x.role].toLowerCase()} à ${ROLE_NAMES[to].toLowerCase()}. ` +
        "L'attribution est signée par ce poste et envoyée au serveur tout de suite.",
      "Changer le rôle",
    );
    if (!ok || !this.locker) {
      select.value = x.role;
      return;
    }
    await this.run(async () => {
      if (!this.locker) return;
      await api.grantRole(this.locker, x.member, to, null);
      announce(`Rôle ${ROLE_NAMES[to].toLowerCase()} donné.`);
    });
  }

  /** @param {Member} x */
  async remove(x) {
    const ok = await confirmDialog(
      x.me ? `Quitter « ${this.name} » ?` : "Retirer ce membre ?",
      (x.me
        ? "Vous ne pourrez plus lire ce casier. Un propriétaire devra vous ajouter de nouveau."
        : `Le membre ${x.member.slice(0, 8)}… ne pourra plus lire les versions écrites désormais. `) +
        (x.me ? "" : "Ce qu'il a déjà pu lire, il a pu le copier : changez les mots de passe sensibles sur leurs cibles."),
      x.me ? "Quitter" : "Retirer",
    );
    if (!ok) return;
    await this.run(async () => {
      if (!this.locker) return;
      await api.revokeRole(this.locker, x.member);
      announce(x.me ? "Vous avez quitté le casier." : "Membre retiré. La clé du casier a tourné.");
    });
  }

  async add() {
    const member = /** @type {HTMLInputElement} */ (byId("ajout-membre"));
    const fp = /** @type {HTMLInputElement} */ (byId("ajout-empreinte"));
    const role = /** @type {RoleName} */ (/** @type {HTMLSelectElement} */ (byId("ajout-role")).value);
    if (!member.value.trim()) {
      showError(byId("membres-erreur"), "Saisissez l'identifiant du membre : 32 chiffres hexadécimaux, que le membre lit dans Serveur, Votre identité.");
      member.focus();
      return;
    }
    await this.run(async () => {
      if (!this.locker) return;
      const got = await api.grantRole(this.locker, member.value, role, fp.value.trim() || null);
      member.value = "";
      fp.value = "";
      announce(`Membre ajouté comme ${ROLE_NAMES[role].toLowerCase()}. Empreinte de sa clé : ${grouped(got)}.`, 6000);
    });
  }

  /** Runs one change, then reloads the members and the state. @param {() => Promise<void>} f */
  async run(f) {
    if (this.busy) return;
    this.busy = true;
    showError(byId("membres-erreur"), null);
    try {
      await f();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) {
        this.dialog.close();
        return;
      }
      showError(byId("membres-erreur"), err.message);
    } finally {
      this.busy = false;
    }
    await this.load();
    this.onChanged();
  }
}
