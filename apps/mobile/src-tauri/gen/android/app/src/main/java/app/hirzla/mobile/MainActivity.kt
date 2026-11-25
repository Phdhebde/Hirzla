package app.hirzla.mobile

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.enableEdgeToEdge

/**
 * The interface (ADR 0080 § 8): Tauri's web view. No screenshot, no preview in the recent
 * applications, no projection (FLAG_SECURE, § 7). It starts no core by itself: the
 * application's Rust code asks for the core of the vault it needs, through `HirzlaPlugin`
 * (docs/api-locale.md § 25.13).
 */
class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
  }
}
