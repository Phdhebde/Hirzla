// Screenshots of the main screens in both themes, against the fake core of
// tests/mock-core.js, with Playwright (not a dependency of the project: install it or use a
// global installation, e.g. `NODE_PATH="$(npm root -g)" node scripts/captures.mjs DIR`; set
// CHROME_PATH to use an installed Chrome or Chromium instead of Playwright's own).
// Also checks that every screen loads without a script error and that the keyboard reaches
// the main controls.
import { createRequire } from "node:module";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { mkdirSync } from "node:fs";
import { extname, join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const here = dirname(fileURLToPath(import.meta.url));
const ui = join(here, "..", "ui");
const mock = await readFile(join(here, "..", "tests", "mock-core.js"), "utf8");
const out = process.argv[2] || join(here, "..", "captures");
mkdirSync(out, { recursive: true });
// Optional second argument: "self", "serveur" or "gouvernance" to take only the screens of
// one part (the checks of the others are then skipped too).
const only = process.argv[3] || "";

const TYPES = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".ttf": "font/ttf" };
const server = createServer(async (req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname)).replace(/^([/\\])+/, "");
  if (path === "favicon.ico") {
    // Asked by a full Chrome (CHROME_PATH), not by the application's web view.
    res.writeHead(204).end();
    return;
  }
  const file = join(ui, path || "index.html");
  if (!file.startsWith(ui)) {
    res.writeHead(403).end();
    return;
  }
  try {
    const body = await readFile(file);
    // The same policy as tauri.conf.json, minus the Tauri IPC origins.
    res.writeHead(200, {
      "content-type": TYPES[extname(file)] || "application/octet-stream",
      "content-security-policy":
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
    });
    res.end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}/index.html`;

const browser = await chromium.launch(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {});
const errors = [];
const shots = [];

async function page(theme, state, server) {
  const context = await browser.newContext({
    viewport: { width: 1180, height: 760 },
    deviceScaleFactor: 2,
    colorScheme: theme === "sombre" ? "dark" : "light",
    locale: "fr-FR",
  });
  const p = await context.newPage();
  p.on("pageerror", (e) => errors.push(`${theme}/${state}: ${e.message}`));
  p.on("console", (m) => {
    if (m.type() === "error") errors.push(`${theme}/${state}: ${m.text()}`);
  });
  p.on("request", (r) => {
    if (!r.url().startsWith("http://127.0.0.1")) errors.push(`requête externe : ${r.url()}`);
  });
  await p.addInitScript(`window.__HIRZLA_MOCK__ = ${JSON.stringify({ state, server })};`);
  await p.addInitScript(mock);
  await p.goto(base);
  await p.evaluate(() => document.fonts.ready);
  return p;
}

async function shot(p, name, theme) {
  await p.waitForTimeout(150);
  const file = join(out, `${name}-${theme}.png`);
  await p.screenshot({ path: file });
  shots.push(file);
}

for (const theme of only && only !== "self" ? [] : ["clair", "sombre"]) {
  // First launch.
  let p = await page(theme, "absent");
  await p.waitForSelector("#ecran-creation:not([hidden])");
  await shot(p, "01-creation-du-coffre", theme);
  await p.close();

  // Unlock, with a refused password.
  p = await page(theme, "locked");
  await p.waitForSelector("#ecran-deverrouillage:not([hidden])");
  await p.keyboard.type("mauvais mot de passe");
  await p.keyboard.press("Enter");
  await p.waitForSelector("#deverrouillage-erreur:not([hidden])");
  await shot(p, "02-deverrouillage", theme);

  // Open the vault with the keyboard only.
  await p.keyboard.type("démonstration");
  await p.keyboard.press("Enter");
  await p.waitForSelector("#ecran-coffre:not([hidden])");
  await p.waitForSelector("#liste-secrets li");
  // From the search field, arrow down into the list, then select.
  await p.keyboard.press("ArrowDown");
  await p.keyboard.press("ArrowDown");
  await p.waitForSelector("#fiche-contenu:not([hidden])");
  await shot(p, "03-liste-et-fiche", theme);

  // Reveal the password (timed) — the first "Révéler" button of the record.
  await p.click("#fiche-champs button[aria-label^='Révéler : mot de passe']");
  await p.waitForSelector("#fiche-champs .etat-ouvert");
  await shot(p, "04-secret-revele", theme);

  // Search.
  await p.keyboard.press("Control+f");
  await p.keyboard.type("routeur");
  await p.waitForFunction(() => document.querySelectorAll("#liste-secrets li").length === 1);
  await p.keyboard.press("ArrowDown");
  await p.keyboard.press("ArrowDown");
  await shot(p, "05-recherche", theme);
  await p.fill("#recherche", "");

  // Command palette: secrets and actions from the keyboard.
  await p.keyboard.press("Control+k");
  await p.waitForSelector("#dialogue-palette[open]");
  await p.keyboard.type("ma");
  await p.waitForSelector("#palette-liste li");
  await shot(p, "05b-palette", theme);
  await p.keyboard.press("Escape");
  await p.waitForSelector("#dialogue-palette:not([open])", { state: "attached" });
  await p.dispatchEvent("#recherche", "input");

  // New secret.
  await p.keyboard.press("Control+n");
  await p.waitForSelector("#dialogue-secret[open]");
  await p.keyboard.type("Compte EDF");
  await p.fill("#secret-identifiant", "m.durand@exemple.fr");
  await p.click("#secret-mdp-generer");
  await p.fill("#secret-urls", "https://particulier.edf.fr");
  await p.fill("#secret-etiquettes", "maison, énergie");
  await shot(p, "06-nouveau-secret", theme);
  await p.keyboard.press("Escape");

  // Connections: the record of an SSH connection through a jump host, then an RDP one.
  await p.waitForSelector("#dialogue-secret:not([open])", { state: "attached" });
  await p.click("[data-filtre='type:connexion']");
  await p.waitForFunction(() => document.getElementById("liste-titre")?.textContent === "Connexions");
  await p.click("#opt-00000000000000000000000000000016");
  await p.waitForSelector("#fiche-champs .chaine");
  await shot(p, "06b-connexion-ssh", theme);
  await p.click("#opt-00000000000000000000000000000017");
  await p.waitForFunction(() => document.getElementById("fiche-champs")?.textContent?.includes("ATELIER"));
  await shot(p, "06c-connexion-rdp", theme);

  // A new SSH connection, linked to a key of the vault and to a jump host.
  await p.keyboard.press("Control+n");
  await p.waitForSelector("#dialogue-secret[open]");
  await p.check("input[name='secret-type'][value='ssh']");
  await p.fill("#secret-titre", "Serveur web de préproduction");
  await p.fill("#secret-hote", "preprod.atelier-durand.fr");
  await p.fill("#secret-identifiant", "deploiement");
  await p.selectOption("#secret-cle", { index: 1 });
  await p.selectOption("#secret-rebond", { index: 1 });
  await shot(p, "06d-nouvelle-connexion-ssh", theme);

  // An existing SSH key, read from a file chosen with the system's file picker.
  await p.check("input[name='secret-type'][value='ssh_key']");
  await p.fill("#secret-titre", "");
  await p.click("#secret-fichier-choisir");
  await p.waitForSelector("#secret-fichier-nom.choisi");
  await shot(p, "06e-nouvelle-cle-ssh", theme);
  await p.keyboard.press("Escape");
  await p.waitForSelector("#dialogue-secret:not([open])", { state: "attached" });
  await p.click("[data-filtre='tous']");

  // Generator.
  await p.keyboard.press("Control+g");
  await p.waitForFunction(() => document.querySelector("#generateur-resultat").textContent.length > 0);
  await shot(p, "07-generateur", theme);
  await p.click("#generateur-modes [data-mode='passphrase']");
  await p.waitForFunction(() => document.querySelector("#generateur-resultat").textContent.includes("-"));
  await p.click("#generateur-lot");
  await p.waitForSelector("#generateur-lot-liste li");
  await shot(p, "07b-generateur-phrase-de-passe", theme);

  // Settings, then an import.
  await p.click("[data-vue='reglages']");
  await p.waitForSelector("#reglage-durcissement tr");
  await shot(p, "08-reglages", theme);
  await p.click("#import-csv");
  await p.waitForSelector("#import-resultat:not([hidden])");
  await p.evaluate(() => document.querySelector("#import-resultat").scrollIntoView({ block: "end" }));
  await p.waitForTimeout(4200); // let the earlier announcement fade
  await shot(p, "09-import-csv", theme);

  // KeePass import: choose the base, refused password, then the report.
  await p.click("#import-kdbx");
  await p.waitForSelector("#dialogue-kdbx[open]");
  await p.click("#kdbx-choisir");
  await p.waitForFunction(() => document.querySelector("#kdbx-fichier").textContent.length > 0);
  await p.keyboard.type("faux");
  await p.keyboard.press("Enter");
  await p.waitForSelector("#kdbx-erreur:not([hidden])");
  await shot(p, "10-import-kdbx", theme);
  await p.keyboard.type("keepass");
  await p.keyboard.press("Enter");
  await p.waitForSelector("#dialogue-kdbx", { state: "hidden" });
  await p.evaluate(() => document.querySelector("#import-resultat").scrollIntoView({ block: "end" }));
  await shot(p, "11-import-kdbx-compte-rendu", theme);

  // Vault settings, password change and recovery kit.
  await p.waitForFunction(() => document.querySelector("#reglage-auto").value === "300");
  await p.evaluate(() => document.querySelector("#reglages-coffre").scrollIntoView({ block: "start" }));
  await shot(p, "12-reglages-du-coffre", theme);
  await p.selectOption("#reglage-auto", "600");
  await p.click("#form-reglages-coffre button[type=submit]");
  await p.waitForSelector("#reglages-coffre-erreur", { state: "hidden" });
  await p.fill("#recouvrement-parts", "5");
  await p.fill("#recouvrement-seuil", "3");
  await p.click("#recouvrement-creer");
  await p.waitForSelector("#dialogue-confirmation[open]");
  await p.click("#confirmation-oui");
  await p.waitForSelector("#recouvrement-resultat:not([hidden])");
  await p.evaluate(() => document.querySelector("#reglages-recouvrement").scrollIntoView({ block: "start" }));
  await p.waitForTimeout(4200);
  await shot(p, "13-kit-de-recouvrement", theme);

  // History of a secret, then the trash.
  await p.click("[data-vue='secrets'][data-filtre='tous']");
  await p.click("#liste-secrets li");
  await p.click("#fiche-menu summary");
  await p.click("#fiche-historique");
  await p.waitForSelector("#dialogue-historique[open] #historique-liste li");
  await p.click("#historique-liste li:nth-child(2) button");
  await p.waitForFunction(() => [...document.querySelectorAll("#historique-liste .valeur-secrete")].some((e) => e.textContent));
  await shot(p, "14-historique", theme);
  await p.keyboard.press("Escape");
  await p.click("[data-filtre='corbeille']");
  await p.waitForFunction(() => document.querySelector("#liste-titre").textContent === "Corbeille");
  await p.click("#liste-secrets li");
  await p.waitForSelector("#fiche-restaurer:not([hidden])");
  await shot(p, "15-corbeille", theme);
  await p.click("#fiche-restaurer");
  await p.waitForSelector("#liste-vide:not([hidden])");

  // Lock: everything shown is wiped.
  await p.keyboard.press("Control+l");
  await p.waitForSelector("#ecran-deverrouillage:not([hidden])");
  const leftovers = await p.evaluate(() => document.querySelectorAll("#liste-secrets li").length);
  if (leftovers !== 0) errors.push(`${theme}: la liste reste affichée après verrouillage`);

  // Open with the recovery kit.
  await p.waitForSelector("#lien-recouvrement:not([hidden])");
  await p.click("#lien-recouvrement");
  await p.waitForSelector("#dialogue-recouvrement[open]");
  await p.click("#recouvrement-choisir");
  await p.waitForSelector("#recouvrement-fichiers li");
  await p.fill("#recouvrement-mdp", "nouveau mot de passe maître");
  await p.fill("#recouvrement-confirmation", "nouveau mot de passe maître");
  await shot(p, "16-ouvrir-avec-le-kit", theme);
  await p.click("#recouvrement-ouvrir");
  await p.waitForSelector("#ecran-coffre:not([hidden])");
  await p.close();
}

/** Opens the server view from the navigation. */
async function serverView(p) {
  await p.click("[data-vue='serveur']");
  await p.waitForSelector("#vue-serveur:not([hidden])");
  await p.waitForFunction(() => document.querySelector("#identite-membre").textContent.length > 0);
}

/** Waits for the announcements to fade. */
async function quiet(p) {
  await p.waitForFunction(() => document.querySelectorAll("#annonces .annonce").length === 0, null, { timeout: 15000 });
}

const SYNCED = { joined: true, verified: true, synced: true, lastSync: Date.UTC(2026, 10, 15, 13, 42) };

for (const theme of only && only !== "serveur" ? [] : ["clair", "sombre"]) {
  // Self mode: join a server. An invitation fingerprint that does not match is refused.
  let p = await page(theme, "unlocked");
  await p.waitForSelector("#ecran-coffre:not([hidden])");
  if (!(await p.isHidden("#etat-serveur"))) errors.push(`${theme}: état du serveur affiché en mode Self`);
  await serverView(p);
  await p.fill("#rejoindre-adresse", "coffre.atelier-durand.fr");
  await p.click("#rejoindre-ac");
  await p.waitForFunction(() => document.querySelector("#rejoindre-ac-nom").textContent.length > 0);
  await shot(p, "17-rejoindre-un-serveur", theme);
  await p.fill("#rejoindre-empreinte", "AAAAA BBBBB CCCCC DDDDD");
  await p.click("#rejoindre-envoyer");
  await p.waitForSelector("#rejoindre-erreur:not([hidden])");
  await shot(p, "18-empreinte-inattendue", theme);

  // Without the fingerprint: it is shown, to compare out of band and type again.
  await p.fill("#rejoindre-empreinte", "");
  await p.click("#rejoindre-envoyer");
  await p.waitForSelector("#serveur-confirmer:not([hidden])");
  await p.waitForSelector("#bandeau-serveur:not([hidden])");
  await quiet(p);
  await shot(p, "19-confirmer-l-empreinte", theme);
  await p.fill("#confirmer-saisie", "m7qkx-r4pzd-2vnbt-l6wea");
  await p.click("#form-confirmer button[type=submit]");
  await p.waitForSelector("#serveur-connexion:not([hidden])");

  // First synchronisation: shared lockers arrive.
  await p.click("#connexion-synchroniser");
  await p.waitForSelector("#connexion-resultat:not([hidden])");
  await p.waitForSelector("#serveur-casiers tbody tr");
  await quiet(p);
  await shot(p, "20-serveur-synchronise", theme);
  await p.close();

  // Shared lockers in the list, distinguished; the record of one.
  p = await page(theme, "unlocked", SYNCED);
  await p.waitForSelector("#liste-casiers .marque-partage");
  await p.click("#liste-casiers li:nth-child(2) button");
  await p.waitForSelector("#liste-casier-partage:not([hidden])");
  await p.click("#liste-secrets li");
  await p.waitForSelector("#fiche-contenu:not([hidden])");
  await shot(p, "21-casiers-partages", theme);

  // New secret: the locker can be chosen.
  await p.keyboard.press("Control+n");
  await p.waitForSelector("#dialogue-secret[open] #secret-casier-champ:not([hidden])");
  await p.fill("#secret-titre", "Imprimante de l'atelier");
  await shot(p, "22-nouveau-secret-casier-partage", theme);
  await p.keyboard.press("Escape");

  // New shared locker.
  await p.click("#bouton-casier-partage");
  await p.waitForSelector("#dialogue-casier[open]");
  await p.keyboard.type("Chantiers 2027");
  await shot(p, "23-nouveau-casier-partage", theme);
  await p.keyboard.press("Enter");
  await p.waitForSelector("#dialogue-casier", { state: "hidden" });
  await p.waitForFunction(() => [...document.querySelectorAll("#liste-casiers .nom-casier")].some((e) => e.textContent === "Chantiers 2027"));

  // Members as the owner: every control enabled, except for the last owner.
  await p.click("#liste-casiers li:nth-child(2) button");
  await p.click("#liste-membres");
  await p.waitForSelector("#dialogue-membres[open] #membres-lignes tr");
  // Adding a member found by its display name: its fingerprint is compared once (ADR 0069).
  await p.fill("#ajout-recherche", "inès");
  await p.click("#ajout-chercher");
  await p.waitForSelector("#ajout-resultats li");
  await p.check("#ajout-resultats li:first-child input");
  await shot(p, "24-membres-proprietaire", theme);
  await p.click("#ajout-envoyer");
  await p.waitForSelector("#dialogue-empreinte[open]");
  await shot(p, "24b-comparer-l-empreinte", theme);
  await p.click("#dialogue-empreinte button[value='oui']");
  await p.waitForFunction(() => document.querySelectorAll("#membres-lignes tr").length === 5);
  await p.keyboard.press("Escape");

  // Members as a reader: disabled, with the reason.
  await p.click("#liste-casiers li:nth-child(3) button");
  await p.click("#liste-membres");
  await p.waitForSelector("#dialogue-membres[open] #membres-lignes tr");
  if (!(await p.evaluate(() => document.querySelector("#membres-ajout").disabled))) errors.push(`${theme}: un lecteur peut ajouter un membre`);
  await quiet(p);
  await shot(p, "25-membres-lecteur", theme);
  await p.keyboard.press("Escape");

  // Server unreachable at the next synchronisation.
  await p.evaluate(() => (window.__HIRZLA_MOCK_SERVER__.failSync = "server_unreachable"));
  await p.click("#bouton-synchroniser");
  await p.waitForSelector("#etat-serveur.etat-alerte");
  await serverView(p);
  await p.waitForSelector("#connexion-erreur:not([hidden])");
  await quiet(p);
  await shot(p, "26-serveur-injoignable", theme);
  await p.close();

  // Access lost to a locker.
  p = await page(theme, "unlocked", { ...SYNCED, lost: true });
  await p.waitForSelector("#bandeau-serveur:not([hidden])");
  await p.click("#liste-casiers li:nth-child(3) button");
  await p.waitForSelector("#liste-casier-partage:not([hidden])");
  await shot(p, "27-acces-perdu", theme);
  await p.close();

  // Suspect key log, and an alert about the member's own keys.
  p = await page(theme, "unlocked", {
    ...SYNCED,
    suspect: true,
    alerts: [{ kind: "unknown_device", index: 131, device: "77c2e0a9b1d34f5e6a7b8c9d0e1f2a3b" }],
  });
  await p.waitForSelector("#bandeau-serveur:not([hidden])");
  await serverView(p);
  await p.waitForSelector("#registre-alertes li");
  // Scroll the view only, not the window: the header and the alert strip stay in sight.
  await p.evaluate(() => {
    const card = document.querySelector("#serveur-registre");
    card.closest(".vue").scrollTop = card.offsetTop - 120;
  });
  await shot(p, "28-registre-suspect", theme);
  // Sharing is refused while the log is suspect.
  await p.click("#casiers-lignes tr:first-child button");
  await p.waitForSelector("#dialogue-membres[open] #membres-lignes tr");
  await p.click("#membres-ajout summary");
  await p.fill("#ajout-membre", "0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a");
  await p.click("#ajout-envoyer");
  await p.waitForSelector("#membres-erreur:not([hidden])");
  await shot(p, "29-partage-refuse-registre-suspect", theme);
  await p.keyboard.press("Escape");

  // Lock: nothing of the server mode stays shown.
  await p.keyboard.press("Control+l");
  await p.waitForSelector("#ecran-deverrouillage:not([hidden])");
  const left = await p.evaluate(() => document.querySelector("#identite-membre").textContent + document.querySelector("#casiers-lignes").childElementCount);
  if (left !== "0") errors.push(`${theme}: l'état du serveur reste affiché après verrouillage`);
  await p.close();
}

// Governance (ADR 0044 to 0048): invitation link, approvals, quarantine, frozen locker.
for (const theme of only && only !== "gouvernance" ? [] : ["clair", "sombre"]) {
  // Join with an invitation link; an altered one is refused.
  let p = await page(theme, "unlocked");
  await p.waitForSelector("#ecran-coffre:not([hidden])");
  await serverView(p);
  const link =
    "hirzla-invitation:pQEBAngmaGlyemxhOi8vY29mZnJlLmF0ZWxpZXItZHVyYW5kLmZyOjc0NDMDWQK3LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t" +
    "TUlJQjZqQ0NBVytnQXdJQkFnSVVSbWNkYjRxVjJ6RTdLeFhwTjNGaDlWYlRvT1V3Q2dZSUtvWkl6ajBFQXdNd0hqRWNNQm9HQTFVRUF3d1QiTTdRS1hSNFBaRDJWTkJUTDZXRUEi";
  await p.fill("#lien-saisie", link.slice(0, 60) + "XX" + link.slice(62));
  await p.click("#lien-envoyer");
  await p.waitForSelector("#lien-erreur:not([hidden])");
  await shot(p, "30-lien-d-invitation-altere", theme);
  await p.fill("#lien-saisie", link);
  await shot(p, "31-rejoindre-par-lien", theme);
  await p.click("#lien-envoyer");
  await p.waitForSelector("#serveur-connexion:not([hidden])");
  await p.close();

  // A senior owner: removing her takes approvals. Prepare the request from the members.
  p = await page(theme, "unlocked", { ...SYNCED, senior: true });
  await serverView(p);
  await p.click("#casiers-lignes tr:first-child button");
  await p.waitForSelector("#dialogue-membres[open] #membres-lignes tr");
  await quiet(p);
  await shot(p, "32-membres-accord-requis", theme);
  await p.click("#membres-lignes tr:first-child button:has-text('pour le retirer')");
  await p.waitForSelector("#dialogue-accord-preparer[open]");
  await p.click("#preparer-envoyer");
  await p.waitForSelector("#preparer-resultat:not([hidden])");
  await quiet(p);
  await shot(p, "33-demande-preparee", theme);
  await p.keyboard.press("Escape");

  // Another owner signs a request received: inspect, then sign.
  await p.click("#serveur-accords summary");
  await p.click("#accords-signer");
  await p.waitForSelector("#dialogue-accord-signer[open]");
  await p.fill("#signer-saisie", "hirzla-demande:pGEBYQKCUGofDC6bjU8Xo8XgLSL6jBQAx7Kq3mZp9TfR2wVbN4cHdL8sJ6gYkE1uQ0oA5iX");
  await p.click("#signer-examiner");
  await p.waitForSelector("#signer-detail:not([hidden])");
  await shot(p, "34-examiner-une-demande", theme);
  await p.click("#signer-envoyer");
  await p.waitForSelector("#signer-resultat:not([hidden])");
  await quiet(p);
  await shot(p, "35-accord-signe", theme);
  await p.keyboard.press("Escape");

  // Back on the requester's side: add the approval, the quorum is met.
  await p.fill("#accord-ajout-saisie", "hirzla-accord:pGEBYQJQah8MLpuNTxejxeAtIvqMFFBkVt3Hq9ZpL2xR7wNcB6mJ4dK8sY1gE5uA0oQ");
  await p.click("#accord-ajout-envoyer");
  await p.waitForFunction(() => document.querySelector("#accords-lignes button.bouton-principal:not(:disabled)"));
  await quiet(p);
  await p.evaluate(() => {
    const card = document.querySelector("#serveur-accords");
    card.closest(".vue").scrollTop = card.offsetTop - 120;
  });
  await shot(p, "36-accords-quorum-atteint", theme);
  await p.close();

  // Quarantine: two writes of a member removed meanwhile.
  p = await page(theme, "unlocked", { ...SYNCED, quarantine: true });
  await serverView(p);
  await p.click("#casiers-lignes tr:first-child button:has-text('Quarantaine')");
  await p.waitForSelector("#dialogue-quarantaine[open] #quarantaine-lignes tr");
  await p.check("#quarantaine-lignes tr:first-child input");
  await shot(p, "37-quarantaine", theme);
  await p.keyboard.press("Escape");
  await p.close();

  // A removal announced and withheld: writes frozen, alert, automatic synchronisation shown.
  p = await page(theme, "unlocked", {
    ...SYNCED,
    frozen: true,
    alerts: [{ kind: "withheld_removal", index: 152, device: null, locker: "0b3d5f7a9c1e2a4b6c8d0e2f4a6b8c0d" }],
  });
  await p.waitForSelector("#bandeau-serveur:not([hidden])");
  await serverView(p);
  await p.waitForSelector("#registre-alertes li");
  await p.evaluate(() => {
    const card = document.querySelector("#serveur-casiers");
    card.closest(".vue").scrollTop = card.offsetTop - 120;
  });
  await shot(p, "38-casier-gele", theme);
  await p.close();

  // Requests carried by the server (ADR 0070): one to examine, one of mine waiting; then the
  // display name in the identity (ADR 0069).
  p = await page(theme, "unlocked", { ...SYNCED, mail: true });
  await serverView(p);
  await p.waitForSelector("#recues-lignes li");
  await p.waitForSelector("#compte-serveur:not([hidden])");
  await quiet(p);
  await p.evaluate(() => {
    const card = document.querySelector("#serveur-accords");
    card.closest(".vue").scrollTop = card.offsetTop - 16;
  });
  await shot(p, "39-demandes-a-examiner", theme);
  await p.click("#recues-lignes li:first-child button.bouton-principal");
  await p.waitForSelector("#dialogue-confirmation[open]");
  await shot(p, "40-signer-une-demande", theme);
  await p.click("#confirmation-oui");
  await p.waitForFunction(() => document.querySelectorAll("#recues-lignes li").length === 0);
  await quiet(p);
  await p.evaluate(() => {
    const card = document.querySelector("#serveur-identite");
    card.closest(".vue").scrollTop = card.offsetTop - 16;
  });
  await shot(p, "41-nom-affiche", theme);
  await p.close();
}

await browser.close();
server.close();
for (const s of shots) console.log(s);
if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}
