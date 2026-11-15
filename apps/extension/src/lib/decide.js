// Pure decisions of the extension, kept apart so that they can be tested without a browser.

const HEX32 = /^[0-9a-f]{32}$/;

/**
 * Checks what `scripting.executeScript` returned for an injection into the main frame: one
 * result, from frame 0, whose page reports being the top-level document of `expectedOrigin`.
 * Anything else is a refusal, never a partial success.
 * @param {unknown} results
 * @param {string} expectedOrigin
 * @returns {{ok: true, value: object} | {ok: false, reason: string}}
 */
export function checkInjection(results, expectedOrigin) {
  if (!Array.isArray(results) || results.length !== 1) return { ok: false, reason: 'frame' };
  const [r] = results;
  if (!r || typeof r !== 'object' || r.frameId !== 0) return { ok: false, reason: 'frame' };
  const v = r.result;
  if (!v || typeof v !== 'object') return { ok: false, reason: 'inject' };
  if (v.top !== true) return { ok: false, reason: 'frame' };
  if (v.origin !== expectedOrigin) return { ok: false, reason: 'origin' };
  if (v.ok !== true) return { ok: false, reason: typeof v.reason === 'string' ? v.reason : 'inject' };
  return { ok: true, value: v };
}

/**
 * Keeps only well-formed entries from the host's answer to `match`.
 * @param {unknown} entries
 * @returns {{locker: string, id: string, title: string, username: string | null}[]}
 */
export function sanitizeEntries(entries) {
  if (!Array.isArray(entries)) return [];
  const out = [];
  for (const e of entries) {
    if (!e || typeof e !== 'object') continue;
    if (typeof e.locker !== 'string' || !HEX32.test(e.locker)) continue;
    if (typeof e.id !== 'string' || !HEX32.test(e.id)) continue;
    if (typeof e.title !== 'string') continue;
    const username = typeof e.username === 'string' ? e.username : null;
    out.push({ locker: e.locker, id: e.id, title: e.title, username });
  }
  return out;
}

/**
 * Whether a login with this user name already exists among `entries` (the extension does not
 * replace a saved password: that is done in the application).
 * @param {{username: string | null}[]} entries
 * @param {string | null} username
 */
export function alreadySaved(entries, username) {
  const u = username ?? null;
  return entries.some((e) => (e.username ?? null) === u);
}

const MESSAGES = {
  unsupported_page: 'Hirzla ne remplit que les pages servies en https.',
  host_unavailable:
    "L'hôte Hirzla n'est pas installé pour ce navigateur. Voir la notice d'installation de l'extension.",
  host_error: "Réponse non valide de l'hôte Hirzla.",
  core_not_running: "Le noyau Hirzla n'est pas démarré. Ouvrez le coffre avec l'application ou « hirzla unlock ».",
  untrusted_core: "Le processus à l'écoute n'est pas le noyau Hirzla attendu : connexion refusée.",
  core_error: 'La connexion au noyau Hirzla a échoué.',
  no_vault: "Aucun coffre. Créez-le avec l'application ou « hirzla init ».",
  locked: "Le coffre est verrouillé. Ouvrez-le avec l'application ou « hirzla unlock », puis rouvrez Hirzla.",
  not_found: 'Aucun identifiant enregistré pour ce site exact.',
  unauthorized: "Opération refusée par le noyau pour l'extension.",
  invalid_origin: "L'adresse de la page n'est pas une origine https valide.",
  invalid_input: 'Valeur refusée : trop longue ou mal formée.',
  bad_request: "Message refusé par l'hôte Hirzla.",
  throttled: 'Trop d’essais. Réessayez plus tard.',
  busy: 'Le noyau est occupé. Réessayez.',
  navigated: 'La page a changé entre-temps. Rouvrez Hirzla sur la page voulue.',
  frame: 'Remplissage refusé : seul le document principal de la page est rempli.',
  origin: "Remplissage refusé : l'origine de la page ne correspond pas.",
  inject: 'Impossible d’agir sur cette page.',
  no_field: 'Aucun champ de mot de passe visible sur cette page.',
  hidden: 'Remplissage refusé : le champ de mot de passe est masqué ou recouvert.',
  no_password: 'Saisissez d’abord un mot de passe dans la page.',
  exists: 'Un identifiant avec ce nom existe déjà pour ce site. Modifiez-le dans l’application.',
  too_large: 'Réponse trop volumineuse.',
};

/**
 * A message for the user, in French, for an error code of the host, the core or the
 * extension. Unknown codes get a generic message: the code itself is never shown raw.
 * @param {string} code
 */
export function messageFor(code) {
  return Object.prototype.hasOwnProperty.call(MESSAGES, code)
    ? MESSAGES[code]
    : 'Opération impossible.';
}
