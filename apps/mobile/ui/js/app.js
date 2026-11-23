// @ts-check
// Hirzla Android — the screens (ADR 0080 § 8). The only door out of the web view is the
// application's Rust commands (src-tauri/src/commands.rs): no fetch, no network, no file.
// Text is set with textContent only.

/** @type {(cmd: string, args?: object) => Promise<any>} */
// @ts-ignore -- injected by Tauri (withGlobalTauri)
const invoke = window.__TAURI__.core.invoke;

/** @param {string} id */
const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));
/** @param {string} id */
const input = (id) => /** @type {HTMLInputElement} */ (document.getElementById(id));

const ECRANS = ["attente", "creation", "rejoindre", "ouverture", "liste", "detail", "ajout", "reglages"];

/** @param {string} nom */
function montrer(nom) {
  for (const e of ECRANS) $(`ecran-${e}`).hidden = e !== nom;
  window.scrollTo(0, 0);
}

/** @param {unknown} e */
function message(e) {
  if (e && typeof e === "object" && "message" in e) return String(e.message);
  return "Erreur inattendue.";
}

/** @param {HTMLFormElement | HTMLElement} form @param {unknown} e */
function erreur(form, e) {
  const p = /** @type {HTMLElement} */ (form.querySelector(".erreur"));
  if (e === null) {
    p.hidden = true;
    p.textContent = "";
  } else {
    p.textContent = message(e);
    p.hidden = false;
  }
}

/** @type {number | undefined} */
let annonceMinuteur;
/** @param {string} texte */
function annoncer(texte) {
  const a = $("annonce");
  a.textContent = texte;
  a.hidden = false;
  clearTimeout(annonceMinuteur);
  annonceMinuteur = setTimeout(() => (a.hidden = true), 3000);
}

/** Runs `f` with the form's submit button disabled. @param {HTMLFormElement} form @param {() => Promise<void>} f */
async function occupe(form, f) {
  const boutons = form.querySelectorAll("button");
  boutons.forEach((b) => (b.disabled = true));
  try {
    erreur(form, null);
    await f();
  } catch (e) {
    erreur(form, e);
  } finally {
    boutons.forEach((b) => (b.disabled = false));
  }
}

/** @type {{ state: string, fingerprint: boolean, can_enrol: boolean, clipboard_clear_s: number, joined: boolean } | null} */
let etat = null;

/** Groups a code or fingerprint by 5 characters. @param {string} s */
const grouper = (s) => (s.match(/.{1,5}/g) ?? []).join(" ");

/** Whether the shared lockers were synchronised since the vault opened. */
let synchronise = false;

async function demarrer() {
  montrer("attente");
  $("attente-texte").textContent = "Connexion au noyau…";
  $("attente-reessayer").hidden = true;
  try {
    etat = await invoke("app_status");
  } catch (e) {
    $("attente-texte").textContent = message(e);
    $("attente-reessayer").hidden = false;
    return;
  }
  if (!etat) return;
  if (etat.state === "absent") {
    montrer("creation");
  } else if (etat.state === "locked") {
    $("ouverture-empreinte").hidden = !etat.fingerprint;
    input("ouverture-mdp").value = "";
    erreur($("form-ouverture"), null);
    montrer("ouverture");
  } else {
    $("liste-synchroniser").hidden = !etat.joined;
    await afficherListe();
    if (etat.joined && !synchronise) {
      synchronise = true;
      void synchroniser(false);
    }
  }
}

/** Synchronises the shared lockers, then reloads the list. @param {boolean} dire */
async function synchroniser(dire) {
  const b = /** @type {HTMLButtonElement} */ ($("liste-synchroniser"));
  b.disabled = true;
  try {
    const n = await invoke("server_sync");
    if (dire) annoncer(`${n} casier(s) partagé(s) synchronisé(s).`);
    if (!$("ecran-liste").hidden) await chargerListe();
  } catch (e) {
    annoncer(message(e));
  } finally {
    b.disabled = false;
  }
}

$("liste-synchroniser").addEventListener("click", () => void synchroniser(true));

// ---- Joining the member's account (ADR 0081) -------------------------------------------

/** @type {number | undefined} */
let releve;
let rejoindreActif = false;
/** Member fingerprint received with the package, then the one the user confirmed.
 * @type {string | null} */
let empreinteRecue = null;
/** @type {string | null} */
let empreinteConfirmee = null;

/** @param {"form-lien" | "rejoindre-code" | "rejoindre-empreinte" | "form-rejoindre-mdp"} partie */
function etape(partie) {
  for (const id of ["form-lien", "rejoindre-code", "rejoindre-empreinte", "form-rejoindre-mdp"]) $(id).hidden = id !== partie;
}

function arreterReleve() {
  rejoindreActif = false;
  clearTimeout(releve);
}

async function abandonner() {
  arreterReleve();
  try {
    await invoke("enrol_cancel");
  } catch {
    // Nothing to cancel.
  }
  await demarrer();
}

$("creation-rejoindre").addEventListener("click", () => {
  /** @type {HTMLTextAreaElement} */ ($("lien-saisie")).value = "";
  erreur($("form-lien"), null);
  etape("form-lien");
  montrer("rejoindre");
});

$("lien-retour").addEventListener("click", () => montrer("creation"));

$("form-lien").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const form = /** @type {HTMLFormElement} */ (ev.currentTarget);
  occupe(form, async () => {
    const code = await invoke("enrol_start", { link: /** @type {HTMLTextAreaElement} */ ($("lien-saisie")).value });
    $("rejoindre-code-valeur").textContent = grouper(code);
    $("rejoindre-attente").textContent = "En attente du poste…";
    erreur($("rejoindre-code"), null);
    etape("rejoindre-code");
    rejoindreActif = true;
    relever();
  });
});

async function relever() {
  if (!rejoindreActif) return;
  try {
    const fp = await invoke("enrol_wait");
    if (!rejoindreActif) return;
    if (fp) {
      arreterReleve();
      empreinteConfirmee = null;
      empreinteRecue = fp;
      $("rejoindre-empreinte-valeur").textContent = grouper(fp);
      etape("rejoindre-empreinte");
      return;
    }
  } catch (e) {
    // A network loss (screen off, application in the background) is not the end: the
    // package waits 10 minutes in the mailbox. Anything else stops.
    if (e && typeof e === "object" && "code" in e && e.code === "server_unreachable") {
      $("rejoindre-attente").textContent = "Réseau indisponible, nouvel essai…";
      releve = setTimeout(relever, 3000);
      return;
    }
    arreterReleve();
    erreur($("rejoindre-code"), e);
    $("rejoindre-attente").textContent = "";
    return;
  }
  $("rejoindre-attente").textContent = "En attente du poste…";
  releve = setTimeout(relever, 2000);
}

$("rejoindre-annuler").addEventListener("click", () => void abandonner());
$("rejoindre-different").addEventListener("click", () => void abandonner());
$("rejoindre-identique").addEventListener("click", () => {
  // The fingerprint shown and confirmed goes back to the core, which refuses any other.
  empreinteConfirmee = empreinteRecue;
  input("rejoindre-mdp").value = "";
  input("rejoindre-confirmation").value = "";
  erreur($("form-rejoindre-mdp"), null);
  etape("form-rejoindre-mdp");
});

$("form-rejoindre-mdp").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const form = /** @type {HTMLFormElement} */ (ev.currentTarget);
  occupe(form, async () => {
    await invoke("enrol_finish", {
      password: input("rejoindre-mdp").value,
      confirmation: input("rejoindre-confirmation").value,
      fingerprint: empreinteConfirmee ?? "",
    });
    input("rejoindre-mdp").value = "";
    input("rejoindre-confirmation").value = "";
    synchronise = false;
    annoncer("Coffre créé. Votre poste ajoute ce téléphone à vos casiers partagés.");
    await demarrer();
  });
});

// ---- Creation and unlocking ----------------------------------------------------------

$("form-creation").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const form = /** @type {HTMLFormElement} */ (ev.currentTarget);
  occupe(form, async () => {
    await invoke("create_vault", {
      password: input("creation-mdp").value,
      confirmation: input("creation-confirmation").value,
    });
    input("creation-mdp").value = "";
    input("creation-confirmation").value = "";
    await demarrer();
  });
});

$("form-ouverture").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const form = /** @type {HTMLFormElement} */ (ev.currentTarget);
  occupe(form, async () => {
    await invoke("unlock", { password: input("ouverture-mdp").value });
    input("ouverture-mdp").value = "";
    await demarrer();
  });
});

$("ouverture-empreinte").addEventListener("click", () => {
  const form = /** @type {HTMLFormElement} */ ($("form-ouverture"));
  occupe(form, async () => {
    await invoke("unlock_fingerprint");
    await demarrer();
  });
});

$("attente-reessayer").addEventListener("click", demarrer);

// ---- List ----------------------------------------------------------------------------

/** @typedef {{ locker: string, id: string, title: string, username: string | null, hosts: string[] }} Entree */
/** @typedef {{ id: string, name: string, personal: boolean }} Casier */

/** @type {Casier[]} */
let casiers = [];

/** @type {number | undefined} */
let rechercheMinuteur;

async function afficherListe() {
  montrer("liste");
  await chargerListe();
}

async function chargerListe() {
  /** @type {Entree[]} */
  let entrees;
  try {
    const liste = await invoke("list_secrets", { query: input("liste-recherche").value || null });
    entrees = liste.entries;
    casiers = liste.lockers;
  } catch (e) {
    annoncer(message(e));
    await demarrer();
    return;
  }
  const ul = $("liste");
  ul.replaceChildren();
  for (const e of entrees) {
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.type = "button";
    const t = document.createElement("span");
    t.className = "titre";
    t.textContent = e.title;
    const s = document.createElement("span");
    s.className = "sous-titre";
    const casier = casiers.find((c) => c.id === e.locker);
    s.textContent = [e.username, e.hosts[0], casier && !casier.personal ? casier.name : null].filter(Boolean).join(" · ");
    b.append(t, s);
    b.addEventListener("click", () => afficherDetail(e));
    li.append(b);
    ul.append(li);
  }
  $("liste-vide").hidden = entrees.length > 0;
}

$("liste-recherche").addEventListener("input", () => {
  clearTimeout(rechercheMinuteur);
  rechercheMinuteur = setTimeout(chargerListe, 200);
});

$("liste-verrouiller").addEventListener("click", async () => {
  try {
    await invoke("lock");
  } catch (e) {
    annoncer(message(e));
  }
  input("liste-recherche").value = "";
  synchronise = false;
  await demarrer();
});

$("liste-ajouter").addEventListener("click", () => {
  for (const id of ["ajout-titre", "ajout-identifiant", "ajout-mdp", "ajout-url"]) input(id).value = "";
  const select = /** @type {HTMLSelectElement} */ ($("ajout-casier"));
  select.replaceChildren();
  for (const c of casiers) {
    const o = document.createElement("option");
    o.value = c.id;
    o.textContent = c.personal ? `${c.name} (ce téléphone seulement)` : `${c.name} (partagé)`;
    select.append(o);
  }
  erreur($("form-ajout"), null);
  montrer("ajout");
});

$("liste-reglages").addEventListener("click", async () => {
  try {
    etat = await invoke("app_status");
  } catch (e) {
    annoncer(message(e));
    return;
  }
  if (!etat) return;
  input("empreinte-mdp").value = "";
  erreur($("form-empreinte"), null);
  $("empreinte-etat").textContent = etat.fingerprint
    ? "L'empreinte ouvre ce coffre."
    : etat.can_enrol
      ? "L'empreinte n'est pas encore ajoutée."
      : "Ce téléphone ne permet pas l'empreinte : il faut la puce StrongBox et une empreinte enregistrée dans les réglages d'Android.";
  $("empreinte-ajout").hidden = etat.fingerprint || !etat.can_enrol;
  montrer("reglages");
});

// ---- One secret ----------------------------------------------------------------------

/** @type {Entree | null} */
let courant = null;

/** @param {Entree} e */
function afficherDetail(e) {
  courant = e;
  $("detail-titre").textContent = e.title;
  $("detail-hotes").textContent = e.hosts.join(", ");
  $("detail-identifiant").textContent = e.username ?? "—";
  $("detail-mdp").textContent = "••••••••••••";
  $("detail-afficher").textContent = "Afficher";
  montrer("detail");
}

function masquer() {
  $("detail-mdp").textContent = "••••••••••••";
  $("detail-afficher").textContent = "Afficher";
}

$("detail-retour").addEventListener("click", () => {
  masquer();
  courant = null;
  afficherListe();
});

$("detail-afficher").addEventListener("click", async () => {
  if (!courant) return;
  if ($("detail-afficher").textContent === "Masquer") {
    masquer();
    return;
  }
  try {
    const v = await invoke("reveal_field", {
      target: { locker: courant.locker, id: courant.id },
      field: "password",
    });
    $("detail-mdp").textContent = v;
    $("detail-afficher").textContent = "Masquer";
  } catch (e) {
    annoncer(message(e));
  }
});

/** @param {"username" | "password"} field */
async function copier(field) {
  if (!courant) return;
  try {
    const delai = await invoke("copy_field", {
      target: { locker: courant.locker, id: courant.id },
      field,
    });
    annoncer(`Copié. Effacé du presse-papiers dans ${delai} s.`);
  } catch (e) {
    annoncer(message(e));
  }
}

$("detail-copier-identifiant").addEventListener("click", () => copier("username"));
$("detail-copier-mdp").addEventListener("click", () => copier("password"));

// ---- New login -----------------------------------------------------------------------

$("ajout-retour").addEventListener("click", afficherListe);

$("form-ajout").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const form = /** @type {HTMLFormElement} */ (ev.currentTarget);
  occupe(form, async () => {
    await invoke("create_login", {
      login: {
        title: input("ajout-titre").value,
        username: input("ajout-identifiant").value || null,
        password: input("ajout-mdp").value || null,
        url: input("ajout-url").value || null,
        locker: /** @type {HTMLSelectElement} */ ($("ajout-casier")).value || null,
      },
    });
    input("ajout-mdp").value = "";
    annoncer("Secret enregistré.");
    await afficherListe();
  });
});

// ---- Settings: fingerprint -----------------------------------------------------------

$("reglages-retour").addEventListener("click", afficherListe);

$("form-empreinte").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const form = /** @type {HTMLFormElement} */ (ev.currentTarget);
  occupe(form, async () => {
    await invoke("enroll_fingerprint", { password: input("empreinte-mdp").value });
    input("empreinte-mdp").value = "";
    annoncer("Empreinte ajoutée.");
    await afficherListe();
  });
});

// Back to the front: the core may have locked the vault, or been stopped by the system.
document.addEventListener("visibilitychange", () => {
  // Not while joining: the user leaves the application to copy the link.
  if (!$("ecran-rejoindre").hidden) return;
  if (document.visibilityState === "visible") demarrer();
  else masquer();
});

demarrer();
