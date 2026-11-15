// @ts-check
// The only door out of the web view: the commands of the application's Rust process
// (src-tauri/src/commands.rs). No fetch, no network, no file access from here.

/**
 * @typedef {{ code: string, message: string, retry_after_s: number | null }} ApiError
 * @typedef {{ memory_locked: string, dumps_disabled: string, tracing_blocked: string }} Hardening
 * @typedef {{ state: "absent" | "locked" | "unlocked", auto_lock_s: number, clipboard_clear_s: number,
 *   core_version: string, core_hardening: Hardening, app_hardening: Hardening | null,
 *   app_version: string }} Status
 * @typedef {{ locker: string, id: string, kind: string, title: string, username: string | null,
 *   hosts: string[], tags: string[], favorite: boolean, trash: boolean }} Entry
 * @typedef {{ id: string, name: string, personal: boolean }} Locker
 * @typedef {{ entries: Entry[], lockers: Locker[] }} Listing
 * @typedef {{ locker: string, id: string }} SecretRef
 * @typedef {"title" | "username" | "password" | "notes" | "ssh_public_key" | "ssh_passphrase"} FieldName
 * @typedef {{ imported: number, empty: number, refused_lines: number[], totp_skipped: number }} ImportReport
 */

/**
 * @returns {(cmd: string, args?: Record<string, unknown>) => Promise<unknown>}
 */
function tauriInvoke() {
  const w = /** @type {any} */ (window);
  const invoke = w.__TAURI__ && w.__TAURI__.core && w.__TAURI__.core.invoke;
  if (typeof invoke !== "function") {
    throw new Error("Pont Tauri absent");
  }
  return invoke;
}

/**
 * Calls a command; a refusal is turned into an {@link ApiError}.
 * @param {string} cmd
 * @param {Record<string, unknown>} [args]
 * @returns {Promise<any>}
 */
async function call(cmd, args) {
  try {
    return await tauriInvoke()(cmd, args);
  } catch (e) {
    throw toApiError(e);
  }
}

/**
 * @param {unknown} e
 * @returns {ApiError}
 */
export function toApiError(e) {
  if (e && typeof e === "object" && "code" in e && "message" in e) {
    const o = /** @type {any} */ (e);
    return { code: String(o.code), message: String(o.message), retry_after_s: o.retry_after_s ?? null };
  }
  return { code: "internal", message: "Erreur inattendue de l'application.", retry_after_s: null };
}

export const api = {
  /** @returns {Promise<Status>} */
  status: () => call("app_status"),
  /** @param {string} password @param {string} confirmation @returns {Promise<void>} */
  createVault: (password, confirmation) => call("create_vault", { password, confirmation }),
  /** @param {string} password @returns {Promise<void>} */
  unlock: (password) => call("unlock", { password }),
  /** @returns {Promise<void>} */
  lock: () => call("lock"),
  /** @param {string} query @param {boolean} trash @returns {Promise<Listing>} */
  list: (query, trash) => call("list_secrets", { query: query || null, trash }),
  /** @param {SecretRef} target @param {FieldName} field @returns {Promise<string>} */
  reveal: (target, field) => call("reveal_field", { target, field }),
  /** @param {SecretRef} target @param {FieldName} field @returns {Promise<number>} */
  copyField: (target, field) => call("copy_field", { target, field }),
  /** @param {Record<string, unknown>} secret @returns {Promise<SecretRef>} */
  create: (secret) => call("create_secret", { secret }),
  /** @param {SecretRef} target @param {Record<string, unknown>} changes @returns {Promise<void>} */
  update: (target, changes) => call("update_secret", { target, changes }),
  /** @param {SecretRef} target @param {boolean} purge @returns {Promise<void>} */
  remove: (target, purge) => call("delete_secret", { target, purge }),
  /** @param {{length: number, lower: boolean, upper: boolean, digits: boolean, symbols: boolean}} options @returns {Promise<string>} */
  generate: (options) => call("generate_password", { options }),
  /** @returns {Promise<number>} */
  copyGenerated: () => call("copy_generated"),
  /** @returns {Promise<ImportReport>} */
  importCsv: () => call("import_csv"),
};
