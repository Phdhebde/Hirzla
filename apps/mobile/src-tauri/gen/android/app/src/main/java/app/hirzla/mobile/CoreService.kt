package app.hirzla.mobile

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.Process
import android.util.Log

/**
 * The core of one slot (ADR 0080 § 2, ADR 0085 step 5, docs/api-locale.md § 25.13), in the
 * process of that slot: `libhirzla_core_android.so` listens on a Unix socket of the private
 * directory and holds the keys of one vault; the interface process is only a client.
 *
 * Android creates a process only for a declared component: there are sixteen subclasses, one
 * per slot, each declared in the manifest with its own process (`:core0` to `:core15`). A
 * slot that is never started costs nothing. The interface starts a slot with a mode (and the
 * identifier of the vault it expects there); the core derives the vault file from the slot.
 *
 * The first start decides what the process serves; later starts are ignored. When the core
 * stops, or when the system stops the service (application in the background), the process
 * ends: the vault is locked again, as the ADR wants.
 */
abstract class CoreService(private val slot: Int) : Service() {
  companion object {
    private const val TAG = "HirzlaCore"

    /** `first`, `vault` or `new` (hirzla_core::slots). */
    const val EXTRA_MODE = "app.hirzla.mobile.core.MODE"

    /** With `vault`: the identifier of the vault, 32 hexadecimal digits. */
    const val EXTRA_VAULT_ID = "app.hirzla.mobile.core.VAULT_ID"

    /** The service of each slot, by slot number. */
    val SLOTS: Array<Class<out CoreService>> =
      arrayOf(
      CoreService0::class.java,
      CoreService1::class.java,
      CoreService2::class.java,
      CoreService3::class.java,
      CoreService4::class.java,
      CoreService5::class.java,
      CoreService6::class.java,
      CoreService7::class.java,
      CoreService8::class.java,
      CoreService9::class.java,
      CoreService10::class.java,
      CoreService11::class.java,
      CoreService12::class.java,
      CoreService13::class.java,
      CoreService14::class.java,
      CoreService15::class.java)

    /** One core per process: set by the first start. */
    @Volatile private var started = false
  }

  private external fun nativeStart(
    context: Context,
    filesDir: String,
    slot: Int,
    mode: String,
    vaultId: String?
  ): String?

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    val mode = intent?.getStringExtra(EXTRA_MODE)
    if (mode == null) {
      // Started without a mode: nothing to serve, unless a core already runs here.
      if (!started) stopSelf()
      return START_NOT_STICKY
    }
    val vaultId = intent.getStringExtra(EXTRA_VAULT_ID)
    synchronized(CoreService::class.java) {
      if (started) return START_NOT_STICKY
      started = true
    }
    System.loadLibrary("hirzla_core_android")
    val dir = filesDir.absolutePath
    Thread({
      // Returns only when the core cannot start; the message holds no secret.
      val error = nativeStart(applicationContext, dir, slot, mode, vaultId)
      Log.e(TAG, "core of slot $slot stopped: ${error ?: "no message"}")
      Process.killProcess(Process.myPid())
    }, "hirzla-core").start()
    return START_NOT_STICKY
  }

  override fun onBind(intent: Intent?): IBinder? = null

  override fun onDestroy() {
    super.onDestroy()
    // The keys live only in this process: ending it locks the vault.
    Process.killProcess(Process.myPid())
  }
}

class CoreService0 : CoreService(0)
class CoreService1 : CoreService(1)
class CoreService2 : CoreService(2)
class CoreService3 : CoreService(3)
class CoreService4 : CoreService(4)
class CoreService5 : CoreService(5)
class CoreService6 : CoreService(6)
class CoreService7 : CoreService(7)
class CoreService8 : CoreService(8)
class CoreService9 : CoreService(9)
class CoreService10 : CoreService(10)
class CoreService11 : CoreService(11)
class CoreService12 : CoreService(12)
class CoreService13 : CoreService(13)
class CoreService14 : CoreService(14)
class CoreService15 : CoreService(15)
