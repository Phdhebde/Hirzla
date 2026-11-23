// @ts-check
// Server mode (local API version 4, ADR 0032 and 0041): joining a server (by invitation link
// or by its three parts, ADR 0046), confirming its fingerprint, synchronising (also in the
// background, ADR 0048), shared lockers, members and roles, approvals between owners
// (ADR 0044), quarantine and frozen lockers (ADR 0045), the state of the key transparency
// log, and the revocation of an unknown device from its alert (ADR 0059). Members carry a
// display name next to their fingerprint (ADR 0069), and approval requests travel through the
// server (ADR 0070). The core does every network exchange; this page only shows what it
// answers and sends what the user typed.

import { api } from "./api.js";
import { announce, byId, h, showError } from "./dom.js";
import { savePrefs } from "./prefs.js";
import { confirmDialog } from "./vault.js";

/** @typedef {import("./api.js").ApiError} ApiError */
/** @typedef {import("./api.js").ServerStatus} ServerStatus */
/** @typedef {import("./api.js").SharedLocker} SharedLocker */
/** @typedef {import("./api.js").RoleName} RoleName */
/** @typedef {import("./api.js").Refusal} Refusal */
/** @typedef {import("./api.js").Member} Member */
/** @typedef {import("./api.js").QuorumRequest} QuorumRequest */
/** @typedef {import("./api.js").QuorumActionName} QuorumActionName */
/** @typedef {import("./api.js").QuarantinedOp} QuarantinedOp */
/** @typedef {import("./api.js").ReceivedRequest} ReceivedRequest */
/** @typedef {import("./api.js").FoundMember} FoundMember */
/** @typedef {import("./prefs.js").Prefs} Prefs */

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
    quorum: "Ce propriétaire est plus ancien que vous : changer son rôle exige l'accord d'autres propriétaires.",
    last_owner: "Le dernier propriétaire ne peut pas être rétrogradé. Nommez d'abord un autre propriétaire.",
    access_lost: ACCESS_LOST,
  },
  remove: {
    role: "Seul un propriétaire retire un autre membre.",
    quorum: "Ce propriétaire est plus ancien que vous : le retirer exige l'accord d'autres propriétaires.",
    last_owner: "Le dernier propriétaire ne peut pas quitter le casier. Nommez d'abord un autre propriétaire.",
    access_lost: ACCESS_LOST,
  },
});

/** Refusals of a device revocation (ADR 0059), by error code. */
const REVOKE_DEVICE_REFUSALS = /** @type {Record<string, string>} */ ({
  forbidden: "Ce poste ne détient pas votre clé de membre. Révoquez l'appareil depuis un appareil de certification.",
  unsupported: "Cet appareil ne figure dans aucun de vos casiers : la révocation ne peut pas encore être publiée. Prévenez votre administrateur de sécurité.",
  not_found: "Appareil introuvable sur ce poste. Synchronisez, puis réessayez.",
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
  const locker = a.locker ? ` (casier ${a.locker.slice(0, 8)})` : "";
  if (a.kind === "foreign_member_key") {
    return ["Clé de membre usurpée", `Une clé qui n'est pas la vôtre est inscrite à votre nom (entrée ${a.index}).`];
  }
  if (a.kind === "unknown_device") {
    return [
      "Appareil inconnu inscrit à votre nom",
      `Un appareil que vous n'avez pas enrôlé est inscrit à votre nom${device}, entrée ${a.index}. Si vous ne le reconnaissez pas, révoquez-le et prévenez votre administrateur de sécurité.`,
    ];
  }
  if (a.kind === "unknown_revocation") {
    return ["Révocation inconnue", `Une révocation que vous n'avez pas faite est inscrite à votre nom${device}, entrée ${a.index}.`];
  }
  if (a.kind === "withheld_removal") {
    return [
      "Retrait annoncé, non reçu",
      `Le registre annonce le retrait d'un membre${locker}, mais le serveur ne vous a pas transmis l'opération depuis plus d'une heure. Les écritures y sont gelées ; la lecture reste possible.`,
    ];
  }
  if (a.kind === "uninscribed_removal") {
    return [
      "Retrait non inscrit au registre",
      `Un retrait que vous avez publié${locker} n'est pas inscrit au registre des clés depuis plus d'une heure.`,
    ];
  }
  if (a.kind === "unknown_profile") {
    return [
      "Nom affiché inconnu inscrit à votre nom",
      `Un nom affiché que vous n'avez pas choisi est inscrit à votre nom (entrée ${a.index}). Vérifiez votre nom dans Votre identité et prévenez votre administrateur de sécurité.`,
    ];
  }
  if (a.kind === "withheld_inscription") {
    return ["Poste non inscrit au registre", "Le certificat de ce poste n'est pas inscrit au registre des clés depuis plus d'une heure."];
  }
  return [
    "Opérations retenues",
    `Des opérations${locker} attendent depuis plus d'une heure une dépendance que le serveur ne transmet pas.`,
  ];
}

/**
 * How a member is called: its display name when the core verified one, else the start of its
 * identifier. The fingerprint, shown next to it, stays the proof.
 * @param {string | null | undefined} name @param {string | null | undefined} member
 */
function memberLabel(name, member) {
  return name || (member ? `${member.slice(0, 8)}…` : "membre inconnu");
}

/**
 * @param {QuorumActionName} action @param {string} who  The member targeted, as {@link memberLabel} calls it.
 * @param {RoleName | null} role @param {number | null} quorum
 */
function actionText(action, who, role, quorum) {
  if (action === "owner_removal") return `Retirer le propriétaire ${who}`;
  if (action === "owner_role_change") return `Donner au propriétaire ${who} le rôle ${role ? ROLE_NAMES[role].toLowerCase() : "?"}`;
  return `Porter le quorum de propriétaires à ${quorum ?? "?"}`;
}

/**
 * The state of a member key: compared out of band by the user, or not yet.
 * @param {boolean} verified
 */
function keyState(verified) {
  return verified
    ? h("span", { class: "etat etat-scelle" }, [h("span", { class: "forme forme-carre", "aria-hidden": "true" }), "Clé vérifiée"])
    : h("span", { class: "etat etat-alerte" }, [h("span", { class: "forme forme-triangle", "aria-hidden": "true" }), "Clé à vérifier"]);
}

/**
 * Asks the user to compare the fingerprint of a member out of band, and records the
 * comparison in the core (ADR 0069).
 * @param {string} member @param {string} label @param {string} fingerprint
 * @returns {Promise<boolean>} True once the core recorded it. A refusal is thrown.
 */
async function compareFingerprint(member, label, fingerprint) {
  const dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-empreinte"));
  byId("empreinte-titre").textContent = `Comparer l'empreinte de ${label}`;
  byId("empreinte-texte").textContent =
    `Appelez ${label} ou voyez cette personne, et demandez-lui de lire l'empreinte de sa clé, affichée chez elle dans Serveur, Votre identité. ` +
    "Comparez-la à celle-ci, caractère par caractère.";
  byId("empreinte-valeur").textContent = grouped(fingerprint);
  dialog.returnValue = "";
  dialog.showModal();
  const same = await new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "oui"), { once: true });
  });
  if (!same) return false;
  await api.memberVerify(member, fingerprint);
  announce(`Empreinte de ${label} comparée : sa clé est vérifiée sur ce poste.`, 6000);
  return true;
}

/**
 * Copies a non-secret text (a request, an approval) and selects it, so that it can also be
 * copied by hand when the clipboard is refused.
 * @param {HTMLTextAreaElement} area
 */
async function copyText(area) {
  area.select();
  try {
    await navigator.clipboard.writeText(area.value);
    announce("Copié dans le presse-papiers.");
  } catch {
    announce("Le texte est sélectionné : copiez-le avec Ctrl+C.");
  }
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
 * @property {Prefs} prefs  Display preferences, including the background synchronisation.
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
    this.approvals = new ApprovalsCard(hooks, () => void this.refresh());
    this.members.onPrepare = (locker, action, target) => this.approvals.prepare.open(locker, action, target);
    this.quarantine = new QuarantineDialog(hooks, async () => {
      await this.refresh();
      await this.hooks.onChanged();
    });
    /** @type {number | null} Timer of the background synchronisation. */
    this.timer = null;

    byId("form-lien").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.joinLink();
    });
    const every = /** @type {HTMLSelectElement} */ (byId("reglage-synchro"));
    every.value = String(hooks.prefs.sync_min);
    every.addEventListener("change", () => {
      hooks.prefs.sync_min = Number(every.value);
      savePrefs(hooks.prefs);
      this.schedule();
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
    byId("form-nom").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.saveName();
    });
    for (const id of ["casiers-nouveau", "bouton-casier-partage"]) {
      byId(id).addEventListener("click", () => this.lockerDialog.open());
    }
    /** @type {string | null} Device found by its code, waiting for approval (ADR 0081). */
    this.enrolDevice = null;
    byId("form-appareil").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.enrolFetch();
    });
    byId("appareil-ajouter").addEventListener("click", () => void this.enrolApprove());
    byId("appareil-annuler").addEventListener("click", () => this.enrolReset());
  }

  /** Back to the code field. */
  enrolReset() {
    this.enrolDevice = null;
    byId("appareil-trouve").hidden = true;
    byId("appareil-attente").hidden = true;
    byId("form-appareil").hidden = false;
    byId("appareil-empreinte").textContent = "";
    /** @type {HTMLInputElement} */ (byId("appareil-code")).value = "";
    showError(byId("appareil-erreur"), null);
  }

  /** Fetches the keys of the new device by the code it shows, then the fingerprint to compare. */
  async enrolFetch() {
    const input = /** @type {HTMLInputElement} */ (byId("appareil-code"));
    showError(byId("appareil-erreur"), null);
    try {
      const peer = await api.enrolFetch(input.value);
      this.enrolDevice = peer.device;
      byId("appareil-empreinte").textContent = grouped(peer.fingerprint);
      byId("form-appareil").hidden = true;
      byId("appareil-trouve").hidden = false;
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) showError(byId("appareil-erreur"), err.message);
    }
  }

  /** Certifies the device, then waits until it authenticated to add it to the shared lockers. */
  async enrolApprove() {
    const device = this.enrolDevice;
    if (!device) return;
    const wait = byId("appareil-attente");
    byId("appareil-trouve").hidden = true;
    wait.hidden = false;
    try {
      await api.enrolApprove(device);
      wait.textContent = "Appareil certifié. Terminez sur l'appareil (mot de passe maître) ; ce poste attend…";
      for (let i = 0; i < 300 && this.enrolDevice === device; i++) {
        const lockers = await api.enrolComplete(device);
        if (lockers !== null) {
          this.enrolReset();
          announce(`Appareil ajouté à ${count(lockers, "casier partagé", "casiers partagés")}.`, 8000);
          await this.refresh();
          return;
        }
        await new Promise((r) => setTimeout(r, 2000));
      }
      if (this.enrolDevice === device) {
        this.enrolReset();
        showError(byId("appareil-erreur"), "L'appareil ne s'est pas présenté en 10 minutes : recommencez.");
      }
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      this.enrolReset();
      if (!this.hooks.onError(err)) showError(byId("appareil-erreur"), err.message);
    }
  }

  /** @param {string} id @returns {SharedLocker | undefined} */
  locker(id) {
    return this.status?.lockers.find((l) => l.id === id);
  }

  /**
   * (Re)starts the background synchronisation (ADR 0048): only with a server joined and its
   * fingerprint confirmed, at the interval chosen; never in Self mode.
   */
  schedule() {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    const minutes = this.hooks.prefs.sync_min;
    if (!this.status?.joined || !this.status.verified || minutes <= 0) return;
    this.timer = window.setInterval(() => void this.sync(true), minutes * 60_000);
  }

  /** Forgets everything shown: called when the vault locks. */
  wipe() {
    this.status = null;
    this.syncError = null;
    this.schedule();
    this.members.wipe();
    this.approvals.wipe();
    this.quarantine.wipe();
    this.enrolReset();
    /** @type {HTMLTextAreaElement} */ (byId("lien-saisie")).value = "";
    showError(byId("lien-erreur"), null);
    for (const id of ["identite-membre", "identite-empreinte", "identite-poste", "identite-code", "rejoindre-ac-nom"]) {
      byId(id).textContent = "";
    }
    for (const id of ["rejoindre-adresse", "rejoindre-empreinte", "confirmer-saisie", "identite-nom"]) {
      /** @type {HTMLInputElement} */ (byId(id)).value = "";
    }
    for (const id of ["rejoindre-erreur", "confirmer-erreur", "connexion-erreur", "identite-nom-erreur"]) showError(byId(id), null);
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
    if (this.timer === null) this.schedule();
    if (this.status?.joined && this.status.verified) await this.approvals.load();
  }

  /**
   * Revokes an unknown device of the member, from its alert (ADR 0059): signed by the member
   * key on this device, published in every locker where the device appears.
   * @param {string} device
   */
  async revokeDevice(device) {
    const ok = await confirmDialog(
      "Révoquer cet appareil ?",
      `L'appareil ${device.slice(0, 8)}… ne pourra plus lire les nouvelles versions de vos casiers. ` +
        "La révocation est signée par votre clé de membre, publiée dans chaque casier où il figure, dont la clé tourne. " +
        "Elle est définitive. Ce qu'il a déjà pu lire, il a pu le copier : changez les mots de passe sensibles sur leurs cibles.",
      "Révoquer",
    );
    if (!ok) return;
    try {
      const lockers = await api.revokeDevice(device);
      announce(`Appareil révoqué dans ${count(lockers, "casier", "casiers")}. Leur clé a tourné.`, 6000);
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) announce(REVOKE_DEVICE_REFUSALS[err.code] ?? err.message, 8000);
    }
    await this.refresh();
  }

  async loadIdentity() {
    try {
      const id = await api.serverIdentity();
      byId("identite-membre").textContent = id.member;
      byId("identite-empreinte").textContent = grouped(id.fingerprint);
      byId("identite-poste").textContent = id.device;
      byId("identite-code").textContent = grouped(id.control_code);
      /** @type {HTMLInputElement} */ (byId("identite-nom")).value = id.name ?? "";
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) announce(err.message, 6000);
    }
  }

  /** Inscribes the display name typed, or withdraws it when empty (ADR 0069). */
  async saveName() {
    const input = /** @type {HTMLInputElement} */ (byId("identite-nom"));
    const error = byId("identite-nom-erreur");
    showError(error, null);
    try {
      await api.profileSet(input.value);
      announce(input.value.trim() ? "Nom affiché inscrit au registre des clés." : "Nom affiché retiré.", 6000);
      await this.loadIdentity();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) return;
      showError(
        error,
        err.code === "invalid"
          ? "Nom refusé : 64 octets au plus, sans caractère de contrôle ni espace en début ou en fin."
          : err.message,
      );
    }
  }

  render() {
    const s = this.status;
    const joined = !!s?.joined;
    const verified = joined && !!s?.verified;
    byId("form-nom").hidden = !verified;
    byId("serveur-rejoindre").hidden = !s || joined;
    byId("serveur-confirmer").hidden = !joined || verified;
    for (const id of ["serveur-connexion", "serveur-registre", "serveur-casiers", "serveur-accords"]) byId(id).hidden = !verified;
    byId("serveur-appareil").hidden = !verified;
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
        /** @type {HTMLButtonElement | null} */
        let revoke = null;
        if (a.kind === "unknown_device" && a.device) {
          const device = a.device;
          revoke = /** @type {HTMLButtonElement} */ (
            h("button", { class: "bouton bouton-secondaire bouton-danger", type: "button", text: "Révoquer cet appareil" })
          );
          revoke.addEventListener("click", () => void this.revokeDevice(device));
        }
        return h("li", { class: "alerte" }, [
          h("p", { class: "alerte-titre" }, [h("span", { class: "forme forme-triangle", "aria-hidden": "true" }), title]),
          h("p", { text }),
          revoke ? h("div", { class: "ligne-actions" }, [revoke]) : null,
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
    const alert = (/** @type {string} */ text) =>
      h("span", { class: "etat etat-alerte" }, [h("span", { class: "forme forme-triangle", "aria-hidden": "true" }), text]);
    const state = !l.access
      ? alert("Accès perdu")
      : l.frozen
        ? alert("Écritures gelées")
        : h("span", { text: notes.length ? notes.join(", ") : "À jour" });
    const members = /** @type {HTMLButtonElement} */ (
      h("button", { class: "bouton bouton-secondaire bouton-petit", type: "button", text: "Membres" })
    );
    const name = l.name ?? "Casier sans nom lisible";
    members.setAttribute("aria-label", `Membres de ${name}`);
    members.addEventListener("click", () => void this.members.open(l.id, name));
    /** @type {HTMLButtonElement | null} */
    let quarantine = null;
    if (l.quarantined > 0 && l.access) {
      quarantine = /** @type {HTMLButtonElement} */ (
        h("button", { class: "bouton bouton-secondaire bouton-petit", type: "button", text: "Quarantaine" })
      );
      quarantine.setAttribute("aria-label", `Quarantaine de ${name}`);
      quarantine.addEventListener("click", () => void this.quarantine.open(l.id, name));
    }
    return h("tr", {}, [
      h("td", {}, [h("span", { text: name }), h("span", { class: "refus mono", text: l.id.slice(0, 8) })]),
      h("td", { text: l.role ? ROLE_NAMES[l.role] : "Aucun rôle" }),
      h("td", {}, [state]),
      h("td", {}, [members, quarantine ? " " : null, quarantine]),
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
    const frozen = s?.lockers.filter((l) => l.access && l.frozen) ?? [];
    if (s?.keylog?.suspect) {
      title = "Registre des clés suspect : le partage est suspendu.";
      detail = "Le serveur présente un registre des clés incohérent. Prévenez votre administrateur de sécurité.";
    } else if (frozen.length > 0) {
      const names = frozen.map((l) => `« ${l.name ?? l.id.slice(0, 8)} »`).join(", ");
      title = "Écritures gelées dans un casier partagé.";
      detail = `Une révocation annoncée par le registre n'a pas été reçue : ${names} reste lisible, mais rien n'y est écrit. Synchronisez ; si le gel persiste, prévenez votre administrateur de sécurité.`;
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

  async joinLink() {
    const area = /** @type {HTMLTextAreaElement} */ (byId("lien-saisie"));
    const error = byId("lien-erreur");
    const button = /** @type {HTMLButtonElement} */ (byId("lien-envoyer"));
    if (!area.value.trim()) {
      showError(error, "Collez le lien d'invitation que l'administrateur vous a remis.");
      area.focus();
      return;
    }
    showError(error, null);
    button.disabled = true;
    button.textContent = "Connexion au serveur…";
    try {
      const r = await api.serverJoinLink(area.value);
      area.value = "";
      announce(
        r.account
          ? "Serveur rattaché par le lien d'invitation, empreinte vérifiée. Le serveur reconnaît votre compte."
          : "Serveur rattaché, empreinte vérifiée. Le serveur ne connaît pas encore votre compte : transmettez votre identité à l'administrateur.",
        8000,
      );
      await this.refresh();
      byId("connexion-synchroniser").focus();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) showError(error, err.message);
    } finally {
      button.disabled = false;
      button.textContent = "Rejoindre avec le lien";
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

  /** @param {boolean} [background] From the timer: no announcement, nothing moves. */
  async sync(background = false) {
    if (this.syncing) return;
    if (background && (!this.status?.joined || !this.status.verified)) return;
    this.syncing = true;
    if (!background) byId("connexion-resultat").hidden = true;
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
      if (!background) {
        const box = byId("connexion-resultat");
        box.textContent = text;
        box.hidden = false;
        announce(text);
      }
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
    /** @type {(locker: string, action: QuorumActionName, target: Member | null) => void} */
    this.onPrepare = () => {};
    /** @type {FoundMember | null} Member chosen among the results of a search. */
    this.chosen = null;
    byId("ajout-envoyer").addEventListener("click", () => void this.add());
    byId("ajout-chercher").addEventListener("click", () => void this.search());
    byId("ajout-recherche").addEventListener("keydown", (e) => {
      // Enter searches; it must not close the dialog (its form has method="dialog").
      if (e.key !== "Enter") return;
      e.preventDefault();
      void this.search();
    });
    byId("membres-quorum-changer").addEventListener("click", () => {
      if (!this.locker) return;
      const locker = this.locker;
      this.dialog.close();
      this.onPrepare(locker, "policy", null);
    });
    this.dialog.addEventListener("close", () => this.wipe());
  }

  wipe() {
    this.locker = null;
    this.chosen = null;
    byId("membres-lignes").replaceChildren();
    byId("ajout-resultats").replaceChildren();
    byId("ajout-resultats-note").textContent = "";
    for (const id of ["ajout-membre", "ajout-empreinte", "ajout-recherche"]) /** @type {HTMLInputElement} */ (byId(id)).value = "";
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
    byId("membres-quorum").textContent = m.quorum
      ? `Quorum : ${m.quorum} propriétaires doivent agréer le retrait d'un propriétaire plus ancien, un changement de son rôle ou du quorum.`
      : "";
    byId("membres-quorum-changer").hidden = me?.role !== "owner";

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
        "Le nom est celui que le membre a inscrit au registre avec sa clé. Avant le premier partage, vous comparez son " +
        "empreinte une fois, de vive voix ; le noyau vérifie aussi que sa clé est inscrite au registre." +
        (m.grantable.includes("owner") ? "" : " Seul un propriétaire nomme un propriétaire ou un gestionnaire.");
    }
    return true;
  }

  /** @param {Member} x */
  row(x) {
    const label = x.me ? "vous-même" : memberLabel(x.name, x.member);
    const who = h("td", {}, [
      h("span", { class: "nom-membre", text: `${x.name ?? "Sans nom affiché"}${x.me ? " (vous)" : ""}` }),
      h("span", { class: "refus mono", text: `${x.member.slice(0, 16)}…`, title: x.member }),
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
      select.setAttribute("aria-label", `Rôle de ${label}`);
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

    /** @type {HTMLButtonElement | null} */
    let compare = null;
    if (!x.me && !x.verified) {
      compare = /** @type {HTMLButtonElement} */ (h("button", { class: "lien", type: "button", text: "Comparer l'empreinte…" }));
      compare.setAttribute("aria-label", `Comparer l'empreinte de ${label}`);
      compare.addEventListener("click", () => void this.run(async () => void (await compareFingerprint(x.member, label, x.fingerprint))));
    }
    const fp = h("td", {}, [
      h("span", { class: "mono", text: grouped(x.fingerprint) }),
      x.me ? null : keyState(x.verified),
      x.proven ? null : h("span", { class: "preuve-absente", text: "Sans preuve d'inscription au registre" }),
      compare,
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
    /** @type {HTMLElement[]} */
    const ask = [];
    const prepare = (/** @type {QuorumActionName} */ action, /** @type {string} */ text) => {
      const b = /** @type {HTMLButtonElement} */ (h("button", { class: "bouton bouton-secondaire bouton-petit", type: "button", text }));
      b.addEventListener("click", () => {
        if (!this.locker) return;
        const locker = this.locker;
        this.dialog.close();
        this.onPrepare(locker, action, x);
      });
      ask.push(b);
    };
    if (x.remove_refusal === "quorum") prepare("owner_removal", "Demander l'accord pour le retirer…");
    if (x.change_refusal === "quorum") prepare("owner_role_change", "Demander l'accord pour changer son rôle…");
    return h("tr", {}, [who, role, fp, h("td", {}, [remove, why, ...ask])]);
  }

  /**
   * @param {Member} x
   * @param {RoleName} to
   * @param {HTMLSelectElement} select
   */
  async change(x, to, select) {
    const ok = await confirmDialog(
      `Donner le rôle ${ROLE_NAMES[to].toLowerCase()} ?`,
      `${x.me ? "Vous passerez" : `${memberLabel(x.name, x.member)} passera`} de ${ROLE_NAMES[x.role].toLowerCase()} à ${ROLE_NAMES[to].toLowerCase()}. ` +
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
        : `${memberLabel(x.name, x.member)} ne pourra plus lire les versions écrites désormais. `) +
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

  /** Searches the members of the server by display name (ADR 0069). */
  async search() {
    const input = /** @type {HTMLInputElement} */ (byId("ajout-recherche"));
    const note = byId("ajout-resultats-note");
    const list = byId("ajout-resultats");
    showError(byId("membres-erreur"), null);
    this.chosen = null;
    if (input.value.trim().length < 2) {
      list.replaceChildren();
      note.textContent = "Saisissez au moins deux caractères du nom recherché.";
      input.focus();
      return;
    }
    /** @type {import("./api.js").MemberSearch} */
    let found;
    try {
      found = await api.memberSearch(input.value);
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) this.dialog.close();
      else showError(byId("membres-erreur"), err.message);
      return;
    }
    note.textContent =
      found.members.length === 0
        ? "Aucun membre du serveur ne porte ce nom. Un membre n'apparaît qu'après avoir inscrit son nom affiché."
        : found.more
          ? "D'autres membres correspondent : précisez le nom."
          : "";
    list.replaceChildren(
      ...found.members.map((m) => {
        const radio = /** @type {HTMLInputElement} */ (h("input", { type: "radio", name: "ajout-choix", value: m.member }));
        radio.addEventListener("change", () => {
          this.chosen = m;
        });
        return h("li", { class: "demande" }, [
          h("label", { class: "demande-ligne" }, [
            radio,
            h("span", { class: "demande-qui" }, [
              h("span", { class: "demande-titre", text: m.name }),
              h("span", { class: "demande-sous mono", text: `Empreinte ${grouped(m.fingerprint)}` }),
            ]),
            keyState(m.verified),
          ]),
        ]);
      }),
    );
    if (found.members.length === 1) {
      const only = /** @type {HTMLInputElement | null} */ (list.querySelector("input"));
      if (only) only.checked = true;
      this.chosen = found.members[0];
    }
  }

  async add() {
    const member = /** @type {HTMLInputElement} */ (byId("ajout-membre"));
    const fp = /** @type {HTMLInputElement} */ (byId("ajout-empreinte"));
    const role = /** @type {RoleName} */ (/** @type {HTMLSelectElement} */ (byId("ajout-role")).value);
    const chosen = this.chosen;
    if (chosen) {
      await this.run(async () => {
        if (!this.locker) return;
        // A name proves nothing: before a first sharing, the fingerprint is compared once.
        if (!chosen.verified && !(await compareFingerprint(chosen.member, chosen.name, chosen.fingerprint))) {
          showError(byId("membres-erreur"), `${chosen.name} n'a pas été ajouté : son empreinte n'a pas été comparée.`);
          return;
        }
        await api.grantRole(this.locker, chosen.member, role, chosen.fingerprint);
        this.chosen = null;
        byId("ajout-resultats").replaceChildren();
        /** @type {HTMLInputElement} */ (byId("ajout-recherche")).value = "";
        announce(`${chosen.name} ajouté comme ${ROLE_NAMES[role].toLowerCase()}.`, 6000);
      });
      return;
    }
    if (!member.value.trim()) {
      showError(byId("membres-erreur"), "Recherchez un membre par son nom et choisissez-le dans les résultats, ou saisissez son identifiant.");
      byId("ajout-recherche").focus();
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

/** Preparing an approval request (ADR 0044): the core checks that it is needed and possible. */
class PrepareDialog {
  /**
   * @param {ServerHooks} hooks
   * @param {() => Promise<void>} onPrepared
   */
  constructor(hooks, onPrepared) {
    this.hooks = hooks;
    this.onPrepared = onPrepared;
    this.dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-accord-preparer"));
    /** @type {{ locker: string, action: QuorumActionName, target: Member | null } | null} */
    this.what = null;
    this.role = /** @type {HTMLSelectElement} */ (h("select", { class: "saisie", id: "preparer-role" }, [
      h("option", { value: "manager", text: ROLE_NAMES.manager }),
      h("option", { value: "editor", text: ROLE_NAMES.editor }),
      h("option", { value: "reader", text: ROLE_NAMES.reader }),
    ]));
    this.roleField = h("label", { class: "champ", hidden: true }, [
      h("span", { class: "champ-libelle", text: "Nouveau rôle" }),
      this.role,
    ]);
    byId("preparer-quorum-champ").after(this.roleField);
    byId("form-preparer").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.send();
    });
    byId("preparer-copier").addEventListener("click", () => void copyText(/** @type {HTMLTextAreaElement} */ (byId("preparer-demande"))));
    this.dialog.addEventListener("close", () => this.wipe());
  }

  wipe() {
    this.what = null;
    /** @type {HTMLTextAreaElement} */ (byId("preparer-demande")).value = "";
    byId("preparer-resultat").hidden = true;
    byId("preparer-copier").hidden = true;
    byId("preparer-envoyer").hidden = false;
    showError(byId("preparer-erreur"), null);
  }

  /** @param {string} locker @param {QuorumActionName} action @param {Member | null} target */
  open(locker, action, target) {
    this.wipe();
    this.what = { locker, action, target };
    const who = target ? `${memberLabel(target.name, target.member)} (empreinte ${grouped(target.fingerprint)})` : "";
    byId("preparer-action").textContent =
      action === "owner_removal"
        ? `Retirer le propriétaire ${who}. Il est plus ancien que vous : d'autres propriétaires doivent agréer ce retrait.`
        : action === "owner_role_change"
          ? `Changer le rôle du propriétaire ${who}. Il est plus ancien que vous : d'autres propriétaires doivent agréer ce changement.`
          : "Changer le nombre de propriétaires qui doivent agréer les actions sensibles. Le changement lui-même exige le quorum en vigueur.";
    byId("preparer-quorum-champ").hidden = action !== "policy";
    this.roleField.hidden = action !== "owner_role_change";
    this.dialog.showModal();
  }

  async send() {
    if (!this.what) return;
    const { locker, action, target } = this.what;
    const quorum = action === "policy" ? Number(/** @type {HTMLInputElement} */ (byId("preparer-quorum")).value) : null;
    const role = action === "owner_role_change" ? /** @type {RoleName} */ (this.role.value) : null;
    showError(byId("preparer-erreur"), null);
    try {
      const q = await api.quorumPrepare(locker, action, target?.member ?? null, role, quorum);
      /** @type {HTMLTextAreaElement} */ (byId("preparer-demande")).value = q.offer;
      // The request leaves through the server at once; the copy route stays open below.
      let sent = "Elle n'a pas pu partir par le serveur : transmettez-la par copie, ou envoyez-la plus tard depuis Serveur, Vos demandes.";
      try {
        const state = await api.quorumSend(q.request);
        sent = state.queued > 0
          ? "Le serveur n'est pas joignable : elle partira à la prochaine synchronisation."
          : "Elle est envoyée aux autres propriétaires par le serveur.";
      } catch (e) {
        if (this.hooks.onError(/** @type {ApiError} */ (e))) {
          this.dialog.close();
          return;
        }
      }
      byId("preparer-compte").textContent = `Demande préparée : ${q.counted.length} accord sur ${q.required} (le vôtre). ${sent}`;
      byId("preparer-resultat").hidden = false;
      byId("preparer-copier").hidden = false;
      byId("preparer-envoyer").hidden = true;
      byId("preparer-copier").focus();
      await this.onPrepared();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) this.dialog.close();
      else showError(byId("preparer-erreur"), err.message);
    }
  }
}

/** Signing a request received from another owner (ADR 0044): inspect first, then sign. */
class SignDialog {
  /** @param {ServerHooks} hooks */
  constructor(hooks) {
    this.hooks = hooks;
    this.dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-accord-signer"));
    this.input = /** @type {HTMLTextAreaElement} */ (byId("signer-saisie"));
    this.input.addEventListener("input", () => this.reset());
    byId("signer-examiner").addEventListener("click", () => void this.inspect());
    byId("form-signer").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.sign();
    });
    byId("signer-copier").addEventListener("click", () => void copyText(/** @type {HTMLTextAreaElement} */ (byId("signer-accord"))));
    this.dialog.addEventListener("close", () => this.wipe());
  }

  reset() {
    byId("signer-detail").hidden = true;
    byId("signer-resultat").hidden = true;
    byId("signer-copier").hidden = true;
    /** @type {HTMLButtonElement} */ (byId("signer-envoyer")).disabled = true;
    /** @type {HTMLTextAreaElement} */ (byId("signer-accord")).value = "";
    showError(byId("signer-erreur"), null);
  }

  wipe() {
    this.input.value = "";
    this.reset();
  }

  open() {
    this.wipe();
    this.dialog.showModal();
    this.input.focus();
  }

  async inspect() {
    this.reset();
    if (!this.input.value.trim()) {
      showError(byId("signer-erreur"), "Collez la demande reçue : elle commence par « hirzla-demande: ».");
      this.input.focus();
      return;
    }
    try {
      const d = await api.quorumInspect(this.input.value);
      byId("signer-casier").textContent = `${d.name ?? "Casier sans nom lisible"} (${d.locker.slice(0, 8)})`;
      byId("signer-action").textContent = actionText(d.action, memberLabel(d.target_name, d.target), d.role, d.quorum);
      byId("signer-demandeur").textContent = `${memberLabel(d.issuer_name, d.issuer)} · empreinte ${d.issuer_fingerprint ? grouped(d.issuer_fingerprint) : "inconnue ici"}`;
      byId("signer-cible").textContent = d.target
        ? `${memberLabel(d.target_name, d.target)} · empreinte ${d.target_fingerprint ? grouped(d.target_fingerprint) : "inconnue ici"}`
        : "Aucun";
      byId("signer-detail").hidden = false;
      /** @type {HTMLButtonElement} */ (byId("signer-envoyer")).disabled = !d.can_sign;
      if (!d.can_sign) {
        showError(
          byId("signer-erreur"),
          "Vous ne pouvez pas signer cette demande : seul un autre propriétaire du casier, qui n'est ni le demandeur ni le membre visé, peut l'agréer.",
        );
      }
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) this.dialog.close();
      else showError(byId("signer-erreur"), err.message);
    }
  }

  async sign() {
    try {
      const token = await api.quorumApprove(this.input.value);
      /** @type {HTMLTextAreaElement} */ (byId("signer-accord")).value = token;
      byId("signer-resultat").hidden = false;
      byId("signer-copier").hidden = false;
      /** @type {HTMLButtonElement} */ (byId("signer-envoyer")).disabled = true;
      byId("signer-copier").focus();
      announce("Accord signé. Rendez-le au demandeur.");
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) this.dialog.close();
      else showError(byId("signer-erreur"), err.message);
    }
  }
}

/** Pending approval requests of this device, and approvals received (ADR 0044). */
class ApprovalsCard {
  /**
   * @param {ServerHooks} hooks
   * @param {() => void} onApplied
   */
  constructor(hooks, onApplied) {
    this.hooks = hooks;
    this.onApplied = onApplied;
    this.prepare = new PrepareDialog(hooks, () => this.load());
    this.sign = new SignDialog(hooks);
    /** @type {QuorumRequest[]} */
    this.list = [];
    /** @type {ReceivedRequest[]} Requests received through the server, to examine. */
    this.inbox = [];
    /** @type {Map<string, string>} Display names of the members of the lockers concerned. */
    this.names = new Map();
    byId("accords-signer").addEventListener("click", () => this.sign.open());
    byId("form-accord-ajout").addEventListener("submit", (e) => {
      e.preventDefault();
      void this.collect();
    });
  }

  wipe() {
    this.list = [];
    this.inbox = [];
    this.names = new Map();
    byId("accords-lignes").replaceChildren();
    byId("recues-lignes").replaceChildren();
    this.renderCount();
    /** @type {HTMLTextAreaElement} */ (byId("accord-ajout-saisie")).value = "";
    showError(byId("accord-ajout-erreur"), null);
  }

  async load() {
    try {
      this.list = await api.quorumList(null);
      this.inbox = await api.quorumInbox();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) announce(err.message, 6000);
      return;
    }
    // Names of the members the pending requests speak of: one reading per locker concerned.
    const names = new Map();
    for (const locker of new Set(this.list.map((q) => q.locker))) {
      try {
        for (const m of (await api.lockerMembers(locker)).members) if (m.name) names.set(m.member, m.name);
      } catch {
        // Without the members, a request shows identifiers: nothing else is lost.
      }
    }
    this.names = names;
    byId("accords-vide").hidden = this.list.length > 0;
    byId("accords-lignes").replaceChildren(...this.list.map((q) => this.row(q)));
    byId("recues-vide").hidden = this.inbox.length > 0;
    byId("recues-lignes").replaceChildren(...this.inbox.map((r) => this.received(r)));
    this.renderCount();
  }

  /** The number of requests to examine, next to « Serveur » in the navigation. */
  renderCount() {
    const badge = byId("compte-serveur");
    const n = this.inbox.length;
    badge.hidden = n === 0;
    badge.textContent = n === 0 ? "" : String(n);
    if (n === 0) badge.removeAttribute("aria-label");
    else badge.setAttribute("aria-label", count(n, "demande à examiner", "demandes à examiner"));
  }

  /** @param {string | null} member */
  who(member) {
    return memberLabel(member ? this.names.get(member) : null, member);
  }

  /**
   * A request received through the server (ADR 0070). The approver knows the quorum required,
   * never how many approvals the initiator already holds.
   * @param {ReceivedRequest} r
   */
  received(r) {
    const issuer = memberLabel(r.issuer_name, r.issuer);
    const what = actionText(r.action, memberLabel(r.target_name, r.target), r.role, r.quorum);
    const locker = r.name ?? `casier ${r.locker.slice(0, 8)}`;
    const sign = /** @type {HTMLButtonElement} */ (h("button", { class: "bouton bouton-principal", type: "button", text: "Examiner et signer" }));
    sign.disabled = !r.can_sign;
    sign.addEventListener("click", () => void this.respond(r, true));
    const decline = /** @type {HTMLButtonElement} */ (h("button", { class: "bouton bouton-secondaire", type: "button", text: "Refuser" }));
    decline.addEventListener("click", () => void this.respond(r, false));
    const copy = /** @type {HTMLButtonElement} */ (h("button", { class: "lien", type: "button", text: "Copier la demande" }));
    const area = /** @type {HTMLTextAreaElement} */ (h("textarea", { class: "visuellement-cache", readonly: true, tabindex: "-1" }));
    area.value = r.offer;
    copy.addEventListener("click", () => void copyText(area));
    return h("li", { class: "demande" }, [
      h("div", { class: "demande-ligne" }, [
        h("span", { class: "demande-qui" }, [
          h("span", { class: "demande-titre", text: `${what} · ${locker}` }),
          h("span", {
            class: "demande-sous",
            text: `Demandée par ${issuer} · empreinte ${r.issuer_fingerprint ? grouped(r.issuer_fingerprint) : "inconnue ici"} · reçue ${when(r.received_ms)}`,
          }),
          r.target
            ? h("span", {
                class: "demande-sous",
                text: `Membre visé : ${memberLabel(r.target_name, r.target)} · empreinte ${r.target_fingerprint ? grouped(r.target_fingerprint) : "inconnue ici"}`,
              })
            : null,
        ]),
        keyState(r.issuer_verified),
      ]),
      h("p", {
        class: "demande-sous",
        text: `${count(r.required, "accord requis", "accords requis")}, celui du demandeur compris. Seul le demandeur sait combien il en a déjà recueilli.`,
      }),
      h("p", { class: "rappel", text: `Avant de signer, vérifiez de vive voix auprès de ${issuer} que la demande vient bien de cette personne.` }),
      r.can_sign
        ? null
        : h("p", { class: "demande-sous", text: "Vous ne pouvez pas signer cette demande : vous êtes le membre visé, ou vous n'êtes plus propriétaire de ce casier." }),
      h("div", { class: "ligne-actions" }, [sign, decline, copy, area]),
    ]);
  }

  /**
   * Signs or declines a received request; the answer goes back through the server.
   * @param {ReceivedRequest} r
   * @param {boolean} accept
   */
  async respond(r, accept) {
    const issuer = memberLabel(r.issuer_name, r.issuer);
    const what = actionText(r.action, memberLabel(r.target_name, r.target), r.role, r.quorum);
    const ok = accept
      ? await confirmDialog(
          `${what} ?`,
          `Demande de ${issuer}, empreinte ${r.issuer_fingerprint ? grouped(r.issuer_fingerprint) : "inconnue ici"}` +
            `${r.issuer_verified ? "" : " (clé pas encore vérifiée sur ce poste)"}. ` +
            `Avant de signer, vérifiez de vive voix auprès de ${issuer} que la demande vient bien de cette personne. ` +
            "Votre accord est signé par la clé de ce poste et ne vaut que pour cette demande.",
          "Signer",
        )
      : await confirmDialog("Refuser cette demande ?", `${issuer} sera prévenu de votre refus par le serveur.`, "Refuser");
    if (!ok) return;
    try {
      await api.quorumRespond(r.locker, r.request, accept);
      announce(accept ? `Accord signé et renvoyé à ${issuer} par le serveur.` : `Demande refusée. ${issuer} en sera prévenu.`, 6000);
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) return;
      announce(err.message, 8000);
    }
    await this.load();
  }

  /** Sends one of this device's requests to the other owners through the server. @param {QuorumRequest} q */
  async send(q) {
    try {
      const state = await api.quorumSend(q.request);
      announce(
        state.queued > 0
          ? "Serveur injoignable : la demande partira à la prochaine synchronisation."
          : "Demande envoyée aux autres propriétaires par le serveur.",
        6000,
      );
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) return;
      announce(err.message, 8000);
    }
    await this.load();
  }

  /** @param {QuorumRequest} q */
  row(q) {
    const button = (/** @type {string} */ text, /** @type {string} */ kind) =>
      /** @type {HTMLButtonElement} */ (h("button", { class: `bouton ${kind} bouton-petit`, type: "button", text }));
    const copy = button("Copier la demande", "bouton-secondaire");
    const area = /** @type {HTMLTextAreaElement} */ (h("textarea", { class: "visuellement-cache", readonly: true, tabindex: "-1" }));
    area.value = q.offer;
    copy.addEventListener("click", () => void copyText(area));
    const met = q.counted.length >= q.required;
    const apply = button("Appliquer", met ? "bouton-principal" : "bouton-secondaire");
    apply.disabled = !met;
    apply.addEventListener("click", () => void this.apply(q));
    const cancel = button("Abandonner", "bouton-secondaire bouton-danger");
    cancel.addEventListener("click", () => void this.cancel(q));
    const send = button(q.sent_ms ? "Renvoyer" : "Envoyer", "bouton-secondaire");
    send.addEventListener("click", () => void this.send(q));
    const journey =
      q.queued > 0
        ? "En attente d'envoi : le serveur n'est pas joignable"
        : q.sent_ms
          ? `Envoyée ${when(q.sent_ms)}`
          : "Pas encore envoyée par le serveur";
    return h("tr", {}, [
      h("td", {}, [
        h("span", { text: actionText(q.action, this.who(q.target), q.role, q.quorum) }),
        h("span", { class: "refus", text: journey }),
        h("span", { class: "refus mono", text: `Demande ${q.request.slice(0, 8)} · casier ${q.locker.slice(0, 8)}` }),
      ]),
      h("td", {}, [
        h("span", { text: `${q.counted.length} sur ${q.required}` }),
        h("span", { class: "refus", text: met ? "Quorum atteint" : `Il manque ${count(q.required - q.counted.length, "accord", "accords")}` }),
        q.declined.length
          ? h("span", { class: "preuve-absente", text: `Refusée par ${q.declined.map((m) => this.who(m)).join(", ")}` })
          : null,
      ]),
      h("td", {}, [met ? null : send, met ? null : " ", copy, " ", apply, " ", cancel, area]),
    ]);
  }

  async collect() {
    const area = /** @type {HTMLTextAreaElement} */ (byId("accord-ajout-saisie"));
    const error = byId("accord-ajout-erreur");
    if (!area.value.trim()) {
      showError(error, "Collez l'accord reçu : il commence par « hirzla-accord: ».");
      area.focus();
      return;
    }
    showError(error, null);
    try {
      const q = await api.quorumCollect(area.value);
      area.value = "";
      announce(
        q.counted.length >= q.required
          ? "Accord ajouté : le quorum est atteint, vous pouvez appliquer la demande."
          : `Accord ajouté : ${q.counted.length} sur ${q.required}.`,
        6000,
      );
      await this.load();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) showError(error, err.message);
    }
  }

  /** @param {QuorumRequest} q */
  async apply(q) {
    const ok = await confirmDialog(
      `${actionText(q.action, this.who(q.target), q.role, q.quorum)} ?`,
      "L'opération est signée par ce poste avec les accords recueillis, puis envoyée au serveur tout de suite.",
      "Appliquer",
    );
    if (!ok) return;
    try {
      await api.quorumApply(q.request);
      announce("Demande appliquée avec les accords des propriétaires.");
      await this.load();
      this.onApplied();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) announce(err.message, 8000);
    }
  }

  /** @param {QuorumRequest} q */
  async cancel(q) {
    const ok = await confirmDialog("Abandonner la demande ?", "Les accords déjà recueillis pour elle sont oubliés.", "Abandonner");
    if (!ok) return;
    try {
      await api.quorumCancel(q.request);
      await this.load();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) announce(err.message, 6000);
    }
  }
}

/** Quarantined operations of a shared locker (ADR 0045): an owner accepts or rejects them. */
class QuarantineDialog {
  /**
   * @param {ServerHooks} hooks
   * @param {() => Promise<void>} onDecided
   */
  constructor(hooks, onDecided) {
    this.hooks = hooks;
    this.onDecided = onDecided;
    this.dialog = /** @type {HTMLDialogElement} */ (byId("dialogue-quarantaine"));
    /** @type {string | null} */
    this.locker = null;
    this.name = "";
    /** @type {string | null} The current member, never offered to remove. */
    this.me = null;
    byId("quarantaine-accepter").addEventListener("click", () => void this.decide(true));
    byId("quarantaine-rejeter").addEventListener("click", () => void this.decide(false));
    this.dialog.addEventListener("close", () => this.wipe());
  }

  wipe() {
    this.locker = null;
    byId("quarantaine-lignes").replaceChildren();
    showError(byId("quarantaine-erreur"), null);
  }

  /** @param {string} locker @param {string} name */
  async open(locker, name) {
    this.locker = locker;
    this.name = name;
    byId("quarantaine-titre").textContent = `Quarantaine de « ${name} »`;
    if (!(await this.load())) return;
    if (!this.dialog.open) this.dialog.showModal();
  }

  /** @returns {Promise<boolean>} */
  async load() {
    if (!this.locker) return false;
    let q;
    try {
      q = await api.quarantineList(this.locker);
      if (this.me === null) this.me = (await api.serverIdentity()).member;
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (!this.hooks.onError(err)) announce(err.message, 6000);
      return false;
    }
    byId("quarantaine-lignes").replaceChildren(...q.ops.map((o) => this.row(o, q.can_decide)));
    for (const id of ["quarantaine-accepter", "quarantaine-rejeter"]) {
      /** @type {HTMLButtonElement} */ (byId(id)).disabled = !q.can_decide || q.ops.length === 0;
    }
    byId("quarantaine-aide").textContent = q.ops.length === 0
      ? "Aucune modification en quarantaine."
      : q.can_decide
        ? "Cochez les modifications, puis acceptez-les ou rejetez-les. La décision est signée par ce poste et envoyée au serveur."
        : "Seul un propriétaire du casier peut accepter ou rejeter ces modifications.";
    return true;
  }

  /** @param {QuarantinedOp} o @param {boolean} canDecide */
  row(o, canDecide) {
    const box = /** @type {HTMLInputElement} */ (h("input", { type: "checkbox", value: o.op_id }));
    box.disabled = !canDecide;
    const what = o.title ?? (o.class === "control" ? "Opération de contrôle" : "Modification illisible ici");
    box.setAttribute("aria-label", `Choisir : ${what}`);
    /** @type {HTMLButtonElement | null} */
    let remove = null;
    if (canDecide && o.member !== this.me) {
      remove = /** @type {HTMLButtonElement} */ (
        h("button", { class: "bouton bouton-secondaire bouton-danger", type: "button", text: "Retirer ce membre du casier" })
      );
      remove.addEventListener("click", () => void this.removeMember(o.member));
    }
    return h("tr", {}, [
      h("td", {}, [box]),
      h("td", {}, [
        h("span", { text: what }),
        h("span", { class: "refus mono", text: `${o.op_id.slice(0, 16)}…${o.wall_ms ? ` · écrite ${when(o.wall_ms)}` : ""}` }),
      ]),
      h("td", { class: "mono", text: `${o.member.slice(0, 8)}…` }),
      h("td", { text: o.cause === "fork" ? "Branche divergente" : "Écrite pendant le retrait de son auteur" }),
      h("td", { text: when(o.due_ms) }),
      h("td", {}, [remove]),
    ]);
  }

  /**
   * Removes the author of a quarantined operation from the locker (ADR 0059, part 2): the
   * existing `RoleRevoke`, the only removal an owner can sign for another member's device.
   * @param {string} member
   */
  async removeMember(member) {
    const ok = await confirmDialog(
      "Retirer ce membre du casier ?",
      `Le membre ${member.slice(0, 8)}… perd son rôle dans « ${this.name} » : tous ses appareils sont retirés de ce casier, ` +
        "dont la clé tourne. Ce qu'il a déjà pu lire, il a pu le copier : changez les mots de passe sensibles sur leurs cibles. " +
        "Pour ne retirer que l'appareil en cause, demandez-lui de le révoquer depuis un appareil de certification.",
      "Retirer",
    );
    if (!ok || !this.locker) return;
    showError(byId("quarantaine-erreur"), null);
    try {
      await api.revokeRole(this.locker, member);
      announce("Membre retiré. La clé du casier a tourné.");
      await this.load();
      await this.onDecided();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) this.dialog.close();
      else showError(byId("quarantaine-erreur"), err.message);
    }
  }

  /** @param {boolean} accept */
  async decide(accept) {
    if (!this.locker) return;
    const ops = [...this.dialog.querySelectorAll("#quarantaine-lignes input:checked")].map((b) => /** @type {HTMLInputElement} */ (b).value);
    if (ops.length === 0) {
      showError(byId("quarantaine-erreur"), "Cochez au moins une modification.");
      return;
    }
    showError(byId("quarantaine-erreur"), null);
    try {
      await api.quarantineDecide(this.locker, ops, accept);
      announce(accept ? `${count(ops.length, "modification acceptée", "modifications acceptées")}.` : `${count(ops.length, "modification rejetée", "modifications rejetées")}.`);
      await this.load();
      await this.onDecided();
    } catch (e) {
      const err = /** @type {ApiError} */ (e);
      if (this.hooks.onError(err)) this.dialog.close();
      else showError(byId("quarantaine-erreur"), err.message);
    }
  }
}
