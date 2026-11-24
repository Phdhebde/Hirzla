package app.hirzla.mobile

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.content.pm.PackageManager
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.Field
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.Presentations
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger

/**
 * The autofill service (ADR 0080 § 6), in the interface process. It holds no key and never
 * reaches the core: it reads the form (which fields are a user name and a password, in
 * which application), and offers one entry, « Remplir avec Hirzla ». Choosing it opens
 * Hirzla (`AutofillActivity`), where the user opens the vault, picks the secret and
 * confirms; only then are values handed to the system.
 *
 * A web domain is believed only from a browser of the fixed list below (package name and
 * signing certificate). No Digital Asset Links: that would be an outgoing call (rule 7).
 */
class HirzlaAutofillService : AutofillService() {
  companion object {
    const val EXTRA_PACKAGE = "app.hirzla.mobile.autofill.PACKAGE"
    const val EXTRA_LABEL = "app.hirzla.mobile.autofill.LABEL"
    const val EXTRA_CERTIFICATE = "app.hirzla.mobile.autofill.CERTIFICATE"
    const val EXTRA_DOMAIN = "app.hirzla.mobile.autofill.DOMAIN"
    const val EXTRA_USERNAME = "app.hirzla.mobile.autofill.USERNAME"
    const val EXTRA_PASSWORD = "app.hirzla.mobile.autofill.PASSWORD"

    private val requestCodes = AtomicInteger(1)

    /**
     * Browsers whose web domain is believed: package name and SHA-256 of the release
     * signing certificate, as published in Google's list of privileged browsers of the
     * Credential Manager (read on 2026-11-23). Kept up to date by the application's updates.
     */
    private val BROWSERS: Map<String, Set<String>> = mapOf(
      "com.android.chrome" to
        setOf("f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83"),
      "com.chrome.beta" to
        setOf(
          "da633d34b69e63ae2103b49d53ce052fc5f7f3c53aab94fdc2a208bdfd14249c",
          "3d7a1223019aa39d9ea0e3436ab7c0896bfb4fb679f4de5fe7c23f326c8f994a",
        ),
      "org.mozilla.firefox" to
        setOf("a78b62a5165b4494b2fead9e76a280d22d937fee6251aece599446b2ea319b04"),
      "com.brave.browser" to
        setOf("9c2db70513515fdbfbbc585b3edf3d7123d4dc67c94ffd306361c1d79bbf18ac"),
      "com.microsoft.emmx" to
        setOf("01e1999710a82c2749b4d50c445dc85d670b6136089d0a766a73827c82a1eac9"),
      "com.sec.android.app.sbrowser" to
        setOf("34df0e7a9f1cf1892e45c056b4973cd81ccf148a4050d11aea4ac5a65f900a42"),
      "com.vivaldi.browser" to
        setOf("e8a78544655ba8c09817f732768f5689b1662ec4b2bc5a0bc0ec138d33ca3d1e"),
      "com.duckduckgo.mobile.android" to
        setOf("bb7bb31c573c46a1da7fc5c528a6acf432108456feec50810c7f33694eb3d2d4"),
    )
  }

  /** A text field of the form, with the web origin it belongs to. */
  private class Target(val id: AutofillId, val scheme: String?, val domain: String?)

  private class Form {
    var username: Target? = null
    var password: Target? = null
    /** Last plain text field seen before the password: the user name, failing a hint. */
    var lastText: Target? = null
  }

  override fun onFillRequest(
    request: FillRequest,
    cancellationSignal: CancellationSignal,
    callback: FillCallback,
  ) {
    try {
      callback.onSuccess(respond(request))
    } catch (e: Exception) {
      // Nothing to offer; the reason holds no secret and is not logged.
      callback.onSuccess(null)
    }
  }

  /** Nothing is saved from a form in this lot: secrets are created in Hirzla. */
  override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
    callback.onFailure("Hirzla n'enregistre pas depuis un formulaire.")
  }

  private fun respond(request: FillRequest): FillResponse? {
    val structure = request.fillContexts.lastOrNull()?.structure ?: return null
    val target = structure.activityComponent?.packageName ?: return null
    // Hirzla never fills itself.
    if (target == packageName) return null

    val form = Form()
    for (i in 0 until structure.windowNodeCount) {
      walk(structure.getWindowNodeAt(i).rootViewNode, null, null, form)
    }
    val password = form.password
    val username = form.username ?: if (password != null) form.lastText else null
    if (username == null && password == null) return null

    val certificate = certificateOf(target)
    val browser = certificate.isNotEmpty() && BROWSERS[target]?.contains(certificate) == true
    val origin = password ?: username
    // Both fields must belong to the same https page of a listed browser.
    val domain = origin?.domain?.takeIf {
      browser && origin.scheme == "https" &&
        (username == null || password == null || username.domain == password.domain)
    }
    // A web form whose domain cannot be believed is not filled at all: the browser would
    // then stand for every site it shows.
    if (origin?.domain != null && domain == null) return null

    val intent = Intent(this, AutofillActivity::class.java)
      .putExtra(EXTRA_PACKAGE, target)
      .putExtra(EXTRA_LABEL, labelOf(target))
      .putExtra(EXTRA_CERTIFICATE, certificate)
      .putExtra(EXTRA_DOMAIN, domain)
      .putExtra(EXTRA_USERNAME, username?.id)
      .putExtra(EXTRA_PASSWORD, password?.id)
    // Mutable: the system adds its own extras when it starts the authentication.
    val pending = PendingIntent.getActivity(
      this,
      requestCodes.getAndIncrement(),
      intent,
      PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
    )

    val view = RemoteViews(packageName, android.R.layout.simple_list_item_1)
    view.setTextViewText(android.R.id.text1, "Remplir avec Hirzla")
    val presentations = Presentations.Builder().setMenuPresentation(view).build()
    // No value yet: the dataset is completed by `AutofillActivity` after the user's choice.
    val placeholder = Field.Builder().setPresentations(presentations).build()
    val dataset = Dataset.Builder(presentations)
    username?.let { dataset.setField(it.id, placeholder) }
    password?.let { dataset.setField(it.id, placeholder) }
    dataset.setAuthentication(pending.intentSender)
    return FillResponse.Builder().addDataset(dataset.build()).build()
  }

  private fun walk(
    node: AssistStructure.ViewNode,
    scheme: String?,
    domain: String?,
    form: Form,
  ) {
    // A node that names a web domain sets the origin of everything below it.
    val nodeDomain = node.webDomain?.lowercase()?.takeIf { it.isNotEmpty() }
    val here = nodeDomain ?: domain
    val hereScheme = if (nodeDomain != null) node.webScheme?.lowercase() else scheme
    val id = node.autofillId
    if (id != null && node.autofillType == View.AUTOFILL_TYPE_TEXT &&
      node.visibility == View.VISIBLE
    ) {
      val target = Target(id, hereScheme, here)
      when (kind(node)) {
        Kind.PASSWORD -> if (form.password == null) form.password = target
        Kind.USERNAME -> if (form.username == null && form.password == null) form.username = target
        Kind.TEXT -> if (form.password == null) form.lastText = target
        Kind.OTHER -> {}
      }
    }
    for (i in 0 until node.childCount) walk(node.getChildAt(i), hereScheme, here, form)
  }

  private enum class Kind { USERNAME, PASSWORD, TEXT, OTHER }

  private fun kind(node: AssistStructure.ViewNode): Kind {
    val hints = node.autofillHints?.map { it.lowercase() } ?: emptyList()
    if (hints.any { it.contains("password") }) return Kind.PASSWORD
    if (hints.any { it == "username" || it == "emailaddress" || it == "email" }) return Kind.USERNAME

    val html = node.htmlInfo
    if (html != null && html.tag.equals("input", ignoreCase = true)) {
      var type = ""
      var autocomplete = ""
      html.attributes?.forEach { a ->
        when (a.first?.lowercase()) {
          "type" -> type = a.second?.lowercase() ?: ""
          "autocomplete" -> autocomplete = a.second?.lowercase() ?: ""
        }
      }
      return when {
        type == "password" || autocomplete.contains("password") -> Kind.PASSWORD
        autocomplete == "username" || autocomplete == "email" || type == "email" -> Kind.USERNAME
        type == "text" || type == "tel" || type == "" -> Kind.TEXT
        else -> Kind.OTHER
      }
    }

    val input = node.inputType
    if (input and InputType.TYPE_MASK_CLASS != InputType.TYPE_CLASS_TEXT) return Kind.OTHER
    return when (input and InputType.TYPE_MASK_VARIATION) {
      InputType.TYPE_TEXT_VARIATION_PASSWORD,
      InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD,
      InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD -> Kind.PASSWORD
      InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,
      InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS -> Kind.USERNAME
      else -> Kind.TEXT
    }
  }

  /** SHA-256 of the signing certificate of `pkg`, hexadecimal; empty when it cannot be read. */
  private fun certificateOf(pkg: String): String {
    return try {
      val info = packageManager.getPackageInfo(
        pkg,
        PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
      )
      val signing = info.signingInfo ?: return ""
      // Several signers at once: no single identity to compare.
      if (signing.hasMultipleSigners()) return ""
      val signer = signing.apkContentsSigners?.firstOrNull() ?: return ""
      MessageDigest.getInstance("SHA-256").digest(signer.toByteArray())
        .joinToString("") { "%02x".format(it) }
    } catch (e: Exception) {
      ""
    }
  }

  private fun labelOf(pkg: String): String {
    return try {
      val info = packageManager.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
      packageManager.getApplicationLabel(info).toString().take(80).ifBlank { pkg }
    } catch (e: Exception) {
      pkg
    }
  }
}
