package app.hirzla.mobile

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.Process
import android.util.Log

/**
 * The core (ADR 0080 § 2), in the `:core` process: `libhirzla_core_android.so` listens on the
 * Unix socket of the private directory and holds the keys; the interface process is only a
 * client. When the system stops the service (application in the background), the process
 * ends with it: the vault is locked again, as the ADR wants.
 */
class CoreService : Service() {
  companion object {
    private const val TAG = "HirzlaCore"
    @Volatile private var started = false
  }

  private external fun nativeStart(context: Context, filesDir: String): String?

  override fun onCreate() {
    super.onCreate()
    synchronized(CoreService::class.java) {
      if (started) return
      started = true
    }
    System.loadLibrary("hirzla_core_android")
    val dir = filesDir.absolutePath
    Thread({
      // Returns only when the core cannot start; the message holds no secret.
      val error = nativeStart(applicationContext, dir)
      Log.e(TAG, "core stopped: ${error ?: "no message"}")
      Process.killProcess(Process.myPid())
    }, "hirzla-core").start()
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_NOT_STICKY

  override fun onBind(intent: Intent?): IBinder? = null

  override fun onDestroy() {
    super.onDestroy()
    // The keys live only in this process: ending it locks the vault.
    Process.killProcess(Process.myPid())
  }
}
