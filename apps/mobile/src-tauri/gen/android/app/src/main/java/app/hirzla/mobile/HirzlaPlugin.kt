package app.hirzla.mobile

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.util.concurrent.atomic.AtomicBoolean

@InvokeArg
class PromptArgs {
  var title: String = ""
  var subtitle: String = ""
}

@InvokeArg
class CopyArgs {
  var text: String = ""
  var clear_s: Long = 30
}

@InvokeArg
class FillArgs {
  var username: String? = null
  var password: String? = null
}

@InvokeArg
class StartCoreArgs {
  var slot: Int = -1
  var mode: String = ""
  var vault_id: String? = null
}

/**
 * The Kotlin layer of the interface (ADR 0080 § 8), called by the application's Rust code
 * only (no capability grants it to the web view): private directory, start of a core slot,
 * BiometricPrompt, sensitive clipboard and the answer to an autofill request. No key and no
 * vault access here.
 */
@TauriPlugin
class HirzlaPlugin(private val activity: Activity) : Plugin(activity) {
  private val main = Handler(Looper.getMainLooper())

  @Command
  fun filesDir(invoke: Invoke) {
    val ret = JSObject()
    ret.put("path", activity.filesDir.absolutePath)
    invoke.resolve(ret)
  }

  /**
   * Starts the core of a slot, in its own process (docs/api-locale.md § 25.13). A slot
   * already started ignores the request: the caller connects, and checks the vault served.
   * The mode and the identifier are checked by the core itself.
   */
  @Command
  fun startCore(invoke: Invoke) {
    val args = invoke.parseArgs(StartCoreArgs::class.java)
    val service = CoreService.SLOTS.getOrNull(args.slot)
    if (service == null) {
      invoke.reject("slot")
      return
    }
    try {
      val intent = Intent(activity, service).putExtra(CoreService.EXTRA_MODE, args.mode)
      args.vault_id?.let { intent.putExtra(CoreService.EXTRA_VAULT_ID, it) }
      activity.startService(intent)
      invoke.resolve()
    } catch (e: Exception) {
      // The system refuses to start a service for an application in the background.
      invoke.reject("start")
    }
  }

  /**
   * Class 3 biometrics only, no fallback on the device code (ADR 0080 § 4.1). Success
   * opens the 5-second window in which the core may use its StrongBox key.
   */
  @Command
  fun authenticate(invoke: Invoke) {
    val args = invoke.parseArgs(PromptArgs::class.java)
    val done = AtomicBoolean(false)
    fun fail(reason: String) {
      if (done.compareAndSet(false, true)) invoke.reject(reason)
    }
    activity.runOnUiThread {
      try {
        val prompt = BiometricPrompt.Builder(activity)
          .setTitle(args.title)
          .setSubtitle(args.subtitle)
          .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
          .setNegativeButton("Annuler", activity.mainExecutor) { _, _ -> fail("cancelled") }
          .build()
        prompt.authenticate(
          CancellationSignal(),
          activity.mainExecutor,
          object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
              if (done.compareAndSet(false, true)) invoke.resolve()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
              fail("error")
            }
          })
      } catch (e: Exception) {
        fail("unavailable")
      }
    }
  }

  /** The autofill request waiting for an answer (ADR 0080 § 6), if any. */
  @Command
  fun autofillPending(invoke: Invoke) {
    val ret = JSObject()
    val r = AutofillBridge.pending()
    ret.put("pending", r != null)
    if (r != null) {
      ret.put("package", r.packageName)
      ret.put("label", r.label)
      ret.put("certificate", r.certificate)
      if (r.domain != null) ret.put("domain", r.domain)
      ret.put("username", r.username != null)
      ret.put("password", r.password != null)
    }
    invoke.resolve(ret)
  }

  /**
   * Answers the autofill request with the values the user chose, then leaves the front so
   * that the target application comes back: `AutofillActivity` hands them to the system.
   */
  @Command
  fun autofillFill(invoke: Invoke) {
    val args = invoke.parseArgs(FillArgs::class.java)
    val answer = AutofillBridge.Answer(args.username?.toCharArray(), args.password?.toCharArray())
    args.username = null
    args.password = null
    if (!AutofillBridge.answer(answer)) {
      invoke.reject("no request")
      return
    }
    activity.runOnUiThread { activity.moveTaskToBack(true) }
    invoke.resolve()
  }

  /** Abandons the autofill request and gives the front back to the target application. */
  @Command
  fun autofillCancel(invoke: Invoke) {
    val had = AutofillBridge.pending() != null
    AutofillBridge.cancel()
    if (had) activity.runOnUiThread { activity.moveTaskToBack(true) }
    invoke.resolve()
  }

  /** Whether Hirzla is the autofill service chosen in the system settings. */
  @Command
  fun autofillState(invoke: Invoke) {
    val ret = JSObject()
    val manager = activity.getSystemService(AutofillManager::class.java)
    ret.put("supported", manager != null && manager.isAutofillSupported)
    ret.put("enabled", manager != null && manager.hasEnabledAutofillServices())
    invoke.resolve(ret)
  }

  /** Opens the system screen where the user chooses the autofill service. */
  @Command
  fun autofillSettings(invoke: Invoke) {
    activity.runOnUiThread {
      try {
        activity.startActivity(
          Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
            .setData(Uri.parse("package:${activity.packageName}")))
        invoke.resolve()
      } catch (e: Exception) {
        invoke.reject("settings")
      }
    }
  }

  /**
   * Copies a field, marked sensitive (hidden from the clipboard preview and history), and
   * clears it after the vault's delay if it is still the one copied (ADR 0016).
   */
  @Command
  fun copySensitive(invoke: Invoke) {
    val args = invoke.parseArgs(CopyArgs::class.java)
    val text = args.text
    args.text = ""
    val delayMs = args.clear_s.coerceIn(1, 3600) * 1000
    activity.runOnUiThread {
      try {
        val cm = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("Hirzla", text)
        clip.description.extras = PersistableBundle().apply {
          putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
        cm.setPrimaryClip(clip)
        val stamp = cm.primaryClipDescription?.timestamp
        main.postDelayed({
          try {
            val now = cm.primaryClipDescription
            if (now == null || stamp == null || now.timestamp == stamp) cm.clearPrimaryClip()
          } catch (e: Exception) {
            cm.clearPrimaryClip()
          }
        }, delayMs)
        invoke.resolve()
      } catch (e: Exception) {
        invoke.reject("clipboard")
      }
    }
  }
}
