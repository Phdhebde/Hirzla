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

async function page(theme, state) {
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
  await p.addInitScript(`window.__HIRZLA_MOCK__ = { state: ${JSON.stringify(state)} };`);
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

for (const theme of ["clair", "sombre"]) {
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

  // Generator.
  await p.keyboard.press("Control+g");
  await p.waitForFunction(() => document.querySelector("#generateur-resultat").textContent.length > 0);
  await shot(p, "07-generateur", theme);

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
  await p.fill("#reglage-auto", "5");
  await p.click("#form-reglages-coffre button[type=submit]");
  await p.waitForSelector("#reglages-coffre-erreur:not([hidden])");
  await p.fill("#reglage-auto", "600");
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
  await p.click("#fiche-historique");
  await p.waitForSelector("#dialogue-historique[open] #historique-liste li");
  await p.click("#historique-liste li:nth-child(2) button");
  await p.waitForFunction(() => [...document.querySelectorAll("#historique-liste .valeur-secrete")].some((e) => e.textContent));
  await shot(p, "14-historique", theme);
  await p.keyboard.press("Escape");
  await p.click("[data-filtre='corbeille']");
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

await browser.close();
server.close();
for (const s of shots) console.log(s);
if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}
