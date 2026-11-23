package app.hirzla.mobile

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.enableEdgeToEdge

/**
 * The interface (ADR 0080 § 8): Tauri's web view. No screenshot, no preview in the recent
 * applications, no projection (FLAG_SECURE, § 7). Starts the core service, in its own
 * `:core` process, whenever the activity comes to the front.
 */
class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    startCore()
  }

  override fun onResume() {
    super.onResume()
    startCore()
  }

  private fun startCore() {
    startService(Intent(this, CoreService::class.java))
  }
}
