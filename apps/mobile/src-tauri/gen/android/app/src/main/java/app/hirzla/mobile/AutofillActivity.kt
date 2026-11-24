package app.hirzla.mobile

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.Field
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue

/**
 * The step between the autofill service and Hirzla (ADR 0080 § 6). The system starts it, in
 * the task of the target application, when the user chooses « Remplir avec Hirzla ». It has
 * no screen: it opens the request in `AutofillBridge`, brings Hirzla to the front, and when
 * it comes back to the front itself, hands the system the values the user chose, or
 * nothing. Never exported: only the service's own pending intent starts it.
 */
class AutofillActivity : Activity() {
  private var request: AutofillBridge.Request? = null
  private var left = false

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val pkg = intent.getStringExtra(HirzlaAutofillService.EXTRA_PACKAGE)
    // Recreated by the system: the request and its answer are gone with the process.
    if (savedInstanceState != null || pkg == null) {
      setResult(RESULT_CANCELED)
      finish()
      return
    }
    val r = AutofillBridge.Request(
      pkg,
      intent.getStringExtra(HirzlaAutofillService.EXTRA_LABEL) ?: pkg,
      intent.getStringExtra(HirzlaAutofillService.EXTRA_CERTIFICATE) ?: "",
      intent.getStringExtra(HirzlaAutofillService.EXTRA_DOMAIN),
      intent.getParcelableExtra(HirzlaAutofillService.EXTRA_USERNAME, AutofillId::class.java),
      intent.getParcelableExtra(HirzlaAutofillService.EXTRA_PASSWORD, AutofillId::class.java),
    )
    request = r
    AutofillBridge.begin(r)
    startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
  }

  override fun onPause() {
    super.onPause()
    left = true
  }

  override fun onResume() {
    super.onResume()
    // The first time, Hirzla is about to cover this activity; afterwards the user is back.
    if (!left) return
    val r = request ?: return
    request = null
    deliver(r, AutofillBridge.finish(r))
  }

  override fun onDestroy() {
    super.onDestroy()
    request?.let { AutofillBridge.finish(it)?.wipe() }
  }

  private fun deliver(r: AutofillBridge.Request, answer: AutofillBridge.Answer?) {
    var filled = false
    val dataset = Dataset.Builder()
    if (answer != null) {
      // The system takes a `CharSequence` it keeps: a Java string Hirzla cannot wipe
      // (declared limit, ADR 0080 § 6). The intermediate buffers are wiped right after.
      fun set(id: AutofillId?, value: CharArray?) {
        if (id == null || value == null || value.isEmpty()) return
        dataset.setField(id, Field.Builder().setValue(AutofillValue.forText(String(value))).build())
        filled = true
      }
      set(r.username, answer.username)
      set(r.password, answer.password)
      answer.wipe()
    }
    if (filled) {
      setResult(
        RESULT_OK,
        Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset.build()),
      )
    } else {
      setResult(RESULT_CANCELED)
    }
    finish()
  }
}
