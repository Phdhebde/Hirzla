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
 * @typedef {{ locker: string, folders: { id: string, name: string, parent: string | null }[],
 *   placements: [string, string][] }} FolderTree
 * @typedef {{ locker: string, id: string }} SecretRef
 * @typedef {"title" | "username" | "password" | "notes" | "ssh_public_key" | "ssh_passphrase" | "rp_id" | "display_name"} FieldName
 * @typedef {{ imported: number, empty: number, refused_lines: number[], totp_skipped: number }} ImportReport
 * @typedef {{ auto_lock_s: number, clipboard_clear_s: number, lock_on_sleep: boolean,
 *   lock_on_session_lock: boolean }} VaultSettings
 * @typedef {{ keep_in_tray: boolean, tray_available: boolean }} LocalPreferences
 * @typedef {"username" | "password" | "username_password" | "notes" | "ssh_passphrase"} TypedWhat
 * @typedef {{ name: string, path: string, title: string, terminal: boolean, can_remember: boolean }} AutoTypeTarget
 * @typedef {{ version: string, wall_ms: number, state: "active" | "trash" | "purged", title: string,
 *   username: string | null, fields: string[], changed: string[], custom: number }} Version
 * @typedef {{ kit: string, threshold: number, count: number }} RecoveryKit
 * @typedef {"password" | "tpm" | "touchid" | "fido2" | "hello" | "recovery" | "unknown"} MethodKind
 * @typedef {{ rank: number, kind: MethodKind, usable: boolean, needs_pin: boolean }} UnlockMethod
 * @typedef {{ methods: UnlockMethod[], enrollable: MethodKind[] }} UnlockMethods
 * @typedef {{ kit: string, threshold: number, count: number, folder: string, files: string[] }} CreatedKit
 * @typedef {{ imported: number, empty: number, recycled: number, attachments: number, history: number,
 *   custom_skipped: number, totp: number, refused: number }} KdbxReport
 * @typedef {{ password: string | null, file: string, secrets: number, trashed: number, attachments: number,
 *   links_dropped: number }} LockerExported
 * @typedef {{ locker: string, secrets: number, attachments: number, folders: number,
 *   refused: number }} LockerImported
 * @typedef {"owner" | "manager" | "editor" | "reader" | "blind_user" | "auditor"} RoleName
 * @typedef {"role" | "quorum" | "last_owner" | "access_lost"} Refusal
 * @typedef {{ id: string, name: string | null, role: RoleName | null, unsent: number, pending: number,
 *   quarantined: number, access: boolean, frozen: boolean }} SharedLocker
 * @typedef {"foreign_member_key" | "unknown_device" | "unknown_revocation" | "withheld_removal" |
 *   "uninscribed_removal" | "withheld_inscription" | "withheld_operation" | "unknown_profile"} AlertKind
 * @typedef {{ kind: AlertKind, index: number | null, device: string | null, locker: string | null }} KeyLogAlert
 * @typedef {{ suspect: boolean, reason: "root" | "shorter" | "rule" | "peer" | "proof" | null, entries: number,
 *   alerts: KeyLogAlert[] }} KeyLog
 * @typedef {{ joined: boolean, url: string | null, server_id: string | null, fingerprint: string | null,
 *   verified: boolean, last_sync_ms: number | null, keylog: KeyLog | null, lockers: SharedLocker[] }} ServerStatus
 * @typedef {{ member: string, fingerprint: string, device: string, control_code: string, name: string | null }} Identity
 * @typedef {{ fingerprint: string, verified: boolean, account: boolean }} Joined
 * @typedef {{ locker: string, received: number, sent: number, refused: number, access: boolean }} SyncReport
 * @typedef {{ member: string, me: boolean, role: RoleName, devices: number, fingerprint: string, proven: boolean,
 *   change_to: RoleName[], change_refusal: Refusal | null, remove_refusal: Refusal | null, name: string | null,
 *   verified: boolean }} Member
 * @typedef {{ me: string, members: Member[], grantable: RoleName[], grant_refusal: Refusal | null,
 *   quorum: number | null }} Members
 * @typedef {"owner_removal" | "owner_role_change" | "policy"} QuorumActionName
 * @typedef {{ request: string, locker: string, action: QuorumActionName, target: string | null,
 *   role: RoleName | null, quorum: number | null, counted: string[], required: number, offer: string,
 *   created_ms: number, sent_ms: number | null, declined: string[], queued: number }} QuorumRequest
 * @typedef {{ member: string, name: string, fingerprint: string, verified: boolean }} FoundMember
 * @typedef {{ members: FoundMember[], more: boolean }} MemberSearch
 * @typedef {{ request: string, locker: string, name: string | null, action: QuorumActionName, target: string | null,
 *   target_fingerprint: string | null, target_name: string | null, target_verified: boolean, role: RoleName | null,
 *   quorum: number | null, issuer: string, issuer_fingerprint: string | null, issuer_name: string | null,
 *   issuer_verified: boolean, can_sign: boolean, required: number, received_ms: number, offer: string }} ReceivedRequest
 * @typedef {{ locker: string, name: string | null, action: QuorumActionName, target: string | null,
 *   target_fingerprint: string | null, role: RoleName | null, quorum: number | null, issuer: string,
 *   issuer_fingerprint: string | null, can_sign: boolean, target_name: string | null,
 *   issuer_name: string | null }} Inspected
 * @typedef {{ op_id: string, member: string, device: string, cause: "removal" | "fork", class: "data" | "control",
 *   wall_ms: number | null, title: string | null, secret: string | null, received_ms: number,
 *   due_ms: number }} QuarantinedOp
 * @typedef {{ ops: QuarantinedOp[], can_decide: boolean }} Quarantine
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

/**
 * Settings of the generator (ADR 0068), one shape per mode.
 * @typedef {{ mode: "characters", length: number, lower: boolean, upper: boolean, digits: boolean, symbols: boolean,
 *             minimums: [number, number, number, number], symbol_set: string | null, excluded: string,
 *             no_ambiguous: boolean, same_keys: boolean, no_repeat: boolean, start_letter: boolean }
 *   | { mode: "passphrase", words: number, separator: string, capitalize: boolean, digits: number }
 *   | { mode: "pronounceable", syllables: number, capitalize: boolean, digits: number, no_ambiguous: boolean }
 *   | { mode: "pin", length: number, no_repeat: boolean, no_sequence: boolean }
 *   | { mode: "template", template: string, symbol_set: string | null, excluded: string,
 *       no_ambiguous: boolean, same_keys: boolean, no_repeat: boolean }} GeneratorSpec
 * @typedef {{ id: string, target_bits: number, spec: GeneratorSpec }} GeneratorProfile
 * @typedef {{ values: string[], strength: { entropy_millibits: number, pool: number } }} GeneratedBatch
 */

/**
 * SSH and RDP connections (local API version 6, ADR 0067).
 * @typedef {"valid" | "broken" | "trashed" | "wrong_type" | "loop"} LinkState
 * @typedef {{ locker: string, id: string, state: LinkState, title: string | null, host: string | null,
 *   port: number | null, username: string | null, public_key: string | null }} ResolvedLink
 * @typedef {{ kind: "ssh" | "rdp", trashed: boolean, title: string | null, host: string | null,
 *   port: number | null, effective_port: number, username: string | null, domain: string | null,
 *   host_key: string | null, favorite: boolean, has_password: boolean, has_notes: boolean, tags: string[],
 *   ssh_key: ResolvedLink | null, jumps: ResolvedLink[] }} ConnectionCard
 * @typedef {{ title?: string, host?: string, port?: number, username?: string, domain?: string,
 *   password?: string, ssh_key?: SecretRef, jump?: SecretRef, host_key?: string, notes?: string,
 *   favorite?: boolean }} ConnectionFields
 * @typedef {"port" | "username" | "domain" | "password" | "ssh_key" | "jump" | "host_key" | "notes"} ConnectionClear
 */

/**
 * TOTP codes (local API version 13, ADR 0078). The code comes from the core; never the TOTP secret.
 * @typedef {{ code: string, seconds_left: number, period: number, digits: number,
 *   algorithm: "SHA-1" | "SHA-256" | "SHA-512", issuer: string | null }} TotpCode
 */

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
  /** @returns {Promise<GeneratorProfile[]>} */
  generatorProfiles: () => call("generator_profiles"),
  /** @param {GeneratorSpec} spec @param {number} count @returns {Promise<GeneratedBatch>} */
  generateWith: (spec, count) => call("generate_with", { spec, count }),
  /** @param {number} index @returns {Promise<number>} */
  copyGeneratedAt: (index) => call("copy_generated_at", { index }),
  /** @returns {Promise<ImportReport>} */
  importCsv: () => call("import_csv"),

  // Connections (local API version 6).
  /**
   * @param {{ kind: "ssh" | "rdp", locker: string | null, fields: ConnectionFields, tags: string[] }} connection
   * @returns {Promise<SecretRef>}
   */
  createConnection: (connection) => call("create_connection", { connection }),
  /** @param {SecretRef} target @returns {Promise<ConnectionCard>} */
  connectionCard: (target) => call("connection_card", { target }),
  /** @param {SecretRef} target @param {ConnectionFields} set @param {ConnectionClear[]} clear @returns {Promise<void>} */
  updateConnection: (target, set, clear) => call("update_connection", { target, set, clear }),
  /** @returns {Promise<string>} Name of the chosen file. */
  chooseSshKeyFile: () => call("choose_ssh_key_file"),
  /**
   * @param {{ locker: string | null, title: string, passphrase?: string, username?: string, tags: string[] }} key
   * @returns {Promise<SecretRef>}
   */
  createSshKey: (key) => call("create_ssh_key", { key }),

  // Folders inside lockers (local API version 11, ADR 0076).
  /** @returns {Promise<FolderTree[]>} */
  folderTrees: () => call("folder_trees"),
  /** @param {string} locker @param {string} name @param {string | null} parent @returns {Promise<string>} */
  createFolder: (locker, name, parent) => call("create_folder", { locker, name, parent }),
  /** @param {string} locker @param {string} folder @param {string} name @returns {Promise<void>} */
  renameFolder: (locker, folder, name) => call("rename_folder", { locker, folder, name }),
  /** @param {string} locker @param {string} folder @param {string | null} parent @returns {Promise<void>} */
  moveFolder: (locker, folder, parent) => call("move_folder", { locker, folder, parent }),
  /** @param {string} locker @param {string} folder @returns {Promise<number>} Secrets sent to the trash. */
  deleteFolder: (locker, folder) => call("delete_folder", { locker, folder }),
  /** @param {SecretRef} target @param {string | null} folder @returns {Promise<void>} */
  moveSecret: (target, folder) => call("move_secret", { target, folder }),
  // TOTP codes (local API version 13).
  /** @param {SecretRef} target @returns {Promise<TotpCode>} */
  totpCode: (target) => call("totp_code", { target }),
  /** @param {SecretRef} target @param {boolean} next  The code of the next period. @returns {Promise<number>} */
  totpCopy: (target, next) => call("totp_copy", { target, next }),
  /** @param {SecretRef} target @param {string} input  otpauth:// URI or base32 secret. @returns {Promise<void>} */
  totpSet: (target, input) => call("totp_set", { target, input }),
  /** @param {SecretRef} target @returns {Promise<void>} */
  totpClear: (target) => call("totp_clear", { target }),
  /**
   * @param {{ locker: string | null, title: string, input: string, username?: string, tags: string[] }} totp
   * @returns {Promise<SecretRef>}
   */
  totpCreate: (totp) => call("totp_create", { totp }),

  // This workstation (ADR 0071).
  /** @returns {Promise<LocalPreferences>} */
  getPreferences: () => call("get_preferences"),
  /** @param {boolean} keepInTray @returns {Promise<LocalPreferences>} */
  setPreferences: (keepInTray) => call("set_preferences", { keep_in_tray: keepInTray }),

  // Typing into another application (ADR 0072).
  /** @returns {Promise<boolean>} */
  autoTypeAvailable: () => call("auto_type_available"),
  /** @param {SecretRef} target @param {TypedWhat} what @returns {Promise<{ typed: boolean, target: AutoTypeTarget }>} */
  autoTypePrepare: (target, what) => call("auto_type_prepare", { target, what }),
  /** @param {boolean} remember @returns {Promise<void>} */
  autoTypeConfirm: (remember) => call("auto_type_confirm", { remember }),
  /** @returns {Promise<void>} */
  autoTypeCancel: () => call("auto_type_cancel"),
  /** @returns {Promise<string[]>} */
  autoTypeTrusted: () => call("auto_type_trusted"),
  /** @param {string | null} path  One application, or all of them. @returns {Promise<string[]>} */
  autoTypeForget: (path) => call("auto_type_forget", { path }),

  // Self mode (local API version 5).
  /** @returns {Promise<VaultSettings>} */
  getSettings: () => call("get_settings"),
  /** @param {VaultSettings} settings @returns {Promise<void>} */
  setSettings: (settings) => call("set_settings", { settings }),
  /** @param {string} current @param {string} password @param {string} confirmation @returns {Promise<void>} */
  changePassword: (current, password, confirmation) => call("change_password", { current, password, confirmation }),
  /** @param {SecretRef} target @returns {Promise<void>} */
  restore: (target) => call("restore_secret", { target }),
  /** @param {SecretRef} target @returns {Promise<Version[]>} */
  history: (target) => call("secret_history", { target }),
  /** @param {SecretRef} target @param {string} version @param {FieldName} field @returns {Promise<string>} */
  revealVersion: (target, version, field) => call("reveal_version", { target, version, field }),
  /** @param {SecretRef} target @param {string} version @param {FieldName} field @returns {Promise<number>} */
  copyVersion: (target, version, field) => call("copy_version", { target, version, field }),
  /** @param {SecretRef} target @param {string} version @returns {Promise<void>} */
  restoreVersion: (target, version) => call("restore_version", { target, version }),
  /** @returns {Promise<RecoveryKit | null>} */
  recoveryStatus: () => call("recovery_status"),
  /** @param {number} threshold @param {number} count @returns {Promise<CreatedKit>} */
  createRecoveryKit: (threshold, count) => call("create_recovery_kit", { threshold, count }),
  /** @returns {Promise<string[]>} */
  chooseRecoveryShares: () => call("choose_recovery_shares"),
  /** @param {string} password @param {string} confirmation @returns {Promise<void>} */
  recoveryUnlock: (password, confirmation) => call("recovery_unlock", { password, confirmation }),
  /** @returns {Promise<void>} */
  removeRecoveryKit: () => call("remove_recovery_kit"),
  // Hardware unlock methods (local API version 12, ADR 0075).
  /** @returns {Promise<UnlockMethods>} */
  unlockMethods: () => call("list_unlock_methods"),
  /** @param {MethodKind} kind @param {string} password @param {string | null} pin @returns {Promise<number>} */
  enrollMethod: (kind, password, pin) => call("enroll_unlock_method", { kind, password, pin }),
  /** @param {number} rank @param {string | null} pin @returns {Promise<void>} */
  unlockWithMethod: (rank, pin) => call("unlock_with_method", { rank, pin }),
  /** @param {number} rank @returns {Promise<void>} */
  removeMethod: (rank) => call("remove_unlock_method", { rank }),
  // Windows Hello and Touch ID, off by default (ADR 0075 § 4); kept on this workstation.
  /** @returns {Promise<boolean>} */
  classicalUnlock: () => call("get_classical_unlock"),
  /** @param {boolean} allowed @returns {Promise<boolean>} */
  setClassicalUnlock: (allowed) => call("set_classical_unlock", { allowed }),
  /** @returns {Promise<string>} */
  chooseKdbxFile: () => call("choose_kdbx_file"),
  chooseKdbxKeyFile: () => call("choose_kdbx_key_file"),
  clearKdbxKeyFile: () => call("clear_kdbx_key_file"),
  /** @param {string} password @returns {Promise<KdbxReport>} */
  importKdbx: (password) => call("import_kdbx", { password }),

  // Encrypted export of a locker (local API version 10, ADR 0077).
  /**
   * @param {string} locker @param {string} name  Suggests the file name.
   * @param {string | null} password  Null: the core draws a passphrase. @returns {Promise<LockerExported>}
   */
  exportLocker: (locker, name, password) => call("export_locker", { locker, name, password }),
  /** @returns {Promise<number>} */
  copyExportPassword: () => call("copy_export_password"),
  /** @returns {Promise<string>} */
  chooseExportFile: () => call("choose_export_file"),
  /** @param {string} password @param {string | null} name @returns {Promise<LockerImported>} */
  importLocker: (password, name) => call("import_locker", { password, name }),

  // Server mode (local API version 4).
  /** @returns {Promise<ServerStatus>} */
  serverStatus: () => call("server_status"),
  /** @returns {Promise<Identity>} */
  serverIdentity: () => call("server_identity"),
  /** @returns {Promise<string>} */
  exportServerIdentity: () => call("export_server_identity"),
  /** @returns {Promise<string>} */
  chooseServerCa: () => call("choose_server_ca"),
  /** @param {string} url @param {string | null} fingerprint @returns {Promise<Joined>} */
  serverJoin: (url, fingerprint) => call("server_join", { url, fingerprint }),
  /** @param {string} fingerprint @returns {Promise<boolean>} */
  serverConfirm: (fingerprint) => call("server_confirm", { fingerprint }),
  /** @returns {Promise<SyncReport[]>} */
  serverSync: () => call("server_sync"),
  /** @param {string} name @returns {Promise<string>} */
  createSharedLocker: (name) => call("create_shared_locker", { name }),
  /** @param {string} locker @returns {Promise<Members>} */
  lockerMembers: (locker) => call("locker_members", { locker }),
  /** @param {string} locker @param {string} member @param {RoleName} role @param {string | null} fingerprint @returns {Promise<string>} */
  grantRole: (locker, member, role, fingerprint) => call("grant_role", { locker, member, role, fingerprint }),
  /** @param {string} locker @param {string} member @returns {Promise<void>} */
  revokeRole: (locker, member) => call("revoke_role", { locker, member }),
  /** @param {string} device @returns {Promise<number>} Lockers where the revocation was published (ADR 0059). */
  revokeDevice: (device) => call("revoke_device", { device }),
  /** @returns {Promise<{ link: string, size: number, modules: string }>} */
  serverInvitation: () => call("server_invitation"),
  /** @param {string} code @returns {Promise<{ fingerprint: string, device: string }>} */
  enrolFetch: (code) => call("device_enrol_fetch", { code }),
  /** @param {string} device @returns {Promise<void>} */
  enrolApprove: (device) => call("device_enrol_approve", { device }),
  /** @param {string} device @returns {Promise<number | null>} */
  enrolComplete: (device) => call("device_enrol_complete", { device }),

  // Governance (ADR 0044 to 0046).
  /** @param {string} link @returns {Promise<Joined>} */
  serverJoinLink: (link) => call("server_join_link", { link }),
  /**
   * @param {string} locker @param {QuorumActionName} action @param {string | null} target
   * @param {RoleName | null} role @param {number | null} quorum @returns {Promise<QuorumRequest>}
   */
  quorumPrepare: (locker, action, target, role, quorum) => call("quorum_prepare", { locker, action, target, role, quorum }),
  /** @param {string} offer @returns {Promise<Inspected>} */
  quorumInspect: (offer) => call("quorum_inspect", { offer }),
  /** @param {string} offer @returns {Promise<string>} */
  quorumApprove: (offer) => call("quorum_approve", { offer }),
  /** @param {string} token @returns {Promise<QuorumRequest>} */
  quorumCollect: (token) => call("quorum_collect", { token }),
  /** @param {string | null} locker @returns {Promise<QuorumRequest[]>} */
  quorumList: (locker) => call("quorum_list", { locker }),
  /** @param {string} request @returns {Promise<void>} */
  quorumApply: (request) => call("quorum_apply", { request }),
  /** @param {string} request @returns {Promise<void>} */
  quorumCancel: (request) => call("quorum_cancel", { request }),
  // Display names and requests carried by the server (ADR 0069, ADR 0070).
  /** @param {string} name  Empty to withdraw the name. @returns {Promise<void>} */
  profileSet: (name) => call("profile_set", { name }),
  /** @param {string} text @returns {Promise<MemberSearch>} */
  memberSearch: (text) => call("member_search", { text }),
  /** @param {string} member @param {string} fingerprint @returns {Promise<void>} */
  memberVerify: (member, fingerprint) => call("member_verify", { member, fingerprint }),
  /** @param {string} request @returns {Promise<QuorumRequest>} */
  quorumSend: (request) => call("quorum_send", { request }),
  /** @returns {Promise<ReceivedRequest[]>} */
  quorumInbox: () => call("quorum_inbox"),
  /** @param {string} locker @param {string} request @param {boolean} accept @returns {Promise<string | null>} */
  quorumRespond: (locker, request, accept) => call("quorum_respond", { locker, request, accept }),
  /** @param {string} locker @returns {Promise<Quarantine>} */
  quarantineList: (locker) => call("quarantine_list", { locker }),
  /** @param {string} locker @param {string[]} ops @param {boolean} accept @returns {Promise<void>} */
  quarantineDecide: (locker, ops, accept) => call("quarantine_decide", { locker, ops, accept }),
};
