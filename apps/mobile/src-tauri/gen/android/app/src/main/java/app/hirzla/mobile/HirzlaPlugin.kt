package app.hirzla.mobile

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
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

/**
 * The Kotlin layer of the interface (ADR 0080 § 8), called by the application's Rust code
 * only (no capability grants it to the web view): private directory, BiometricPrompt and
 * sensitive clipboard. No key and no vault access here.
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
