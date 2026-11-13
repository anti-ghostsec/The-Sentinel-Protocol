package protocol.sentinel.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  companion object {
    /** A sentinel:// link the app was opened with (the page asks before using it). */
    @Volatile
    var openedLink: String? = null
  }

  private fun keepLink(intent: Intent?) {
    val link = intent?.takeIf { it.action == Intent.ACTION_VIEW }?.dataString ?: return
    if (link.startsWith("sentinel://") && link.length < 1024) openedLink = link
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    keepLink(intent)
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    keepLink(intent)
    enableEdgeToEdge()
    // Always: no screenshots, no screen recording or casting of Sentinel's
    // screen, and a blank preview in the recent-apps list.
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    super.onCreate(savedInstanceState)

    // Keep the page clear of the status bar, the gesture bar, camera
    // cutouts and the keyboard (Android doesn't reliably tell web pages
    // how big these are). Behind the bars: the app's own dark background,
    // with light icons.
    window.decorView.setBackgroundColor(0xFF0A0A0C.toInt())
    WindowCompat.getInsetsController(window, window.decorView).apply {
      isAppearanceLightStatusBars = false
      isAppearanceLightNavigationBars = false
    }
    val content = findViewById<View>(android.R.id.content)
    ViewCompat.setOnApplyWindowInsetsListener(content) { v, insets ->
      val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
      val keyboard = insets.getInsets(WindowInsetsCompat.Type.ime())
      v.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, keyboard.bottom))
      WindowInsetsCompat.CONSUMED
    }
  }
}
