package app.hirzla.mobile

import android.view.autofill.AutofillId

/**
 * The autofill request in progress (ADR 0080 § 6), shared by the activities of the interface
 * process: `AutofillActivity` (started by the system in the task of the target application)
 * opens it, the Hirzla screens answer it through `HirzlaPlugin`, and `AutofillActivity`
 * hands the answer to the system when it comes back to the front. No key and no vault access
 * here; the values filled are held only between the answer and its delivery.
 */
object AutofillBridge {
  /** The form to fill, as the autofill service read it. */
  class Request(
    /** Package of the application that shows the form. */
    val packageName: String,
    /** Its label, for the warning. */
    val label: String,
    /** SHA-256 of its signing certificate, hexadecimal; empty when unknown. */
    val certificate: String,
    /** Web domain of the form, only when the application is a browser of the fixed list. */
    val domain: String?,
    val username: AutofillId?,
    val password: AutofillId?,
  )

  /** The values chosen by the user. Wiped once handed to the system. */
  class Answer(val username: CharArray?, val password: CharArray?) {
    fun wipe() {
      username?.fill('\u0000')
      password?.fill('\u0000')
    }
  }

  private var request: Request? = null
  private var answer: Answer? = null

  /** Opens a request; an earlier one and its answer are dropped. */
  @Synchronized
  fun begin(r: Request) {
    answer?.wipe()
    answer = null
    request = r
  }

  /** The request waiting for an answer, if any. */
  @Synchronized
  fun pending(): Request? = if (answer == null) request else null

  /** Records the answer to the request in progress. False (and wiped) when there is none. */
  @Synchronized
  fun answer(a: Answer): Boolean {
    if (request == null || answer != null) {
      a.wipe()
      return false
    }
    answer = a
    return true
  }

  /** Abandons the request in progress. */
  @Synchronized
  fun cancel() {
    answer?.wipe()
    answer = null
    request = null
  }

  /** Closes `r` and gives its answer, if it is still the request in progress. */
  @Synchronized
  fun finish(r: Request): Answer? {
    if (request !== r) return null
    val a = answer
    answer = null
    request = null
    return a
  }
}
