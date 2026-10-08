package protocol.sentinel.app

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import android.graphics.Matrix
import android.net.Uri
import androidx.activity.result.ActivityResult
import androidx.media3.common.MediaItem
import androidx.media3.common.MimeTypes
import androidx.media3.effect.MatrixTransformation
import androidx.media3.transformer.Composition
import androidx.media3.transformer.EditedMediaItem
import androidx.media3.transformer.Effects
import androidx.media3.transformer.ExportException
import androidx.media3.transformer.ExportResult
import androidx.media3.transformer.Transformer
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import java.security.SecureRandom

// Files on phones (see the app's `android.rs`):
// - picked files are copied into the app's private cache (the app works
//   with file paths; the system only hands out content links);
// - saving writes to the app's private cache first, then into the place
//   the person chose;
// - audio and video are rebuilt with the system's encoders (Media3), so
//   files can't be traced to the recording app or camera by their layout;
//   the app then removes any metadata left;
// - updates: a verified APK goes to the system installer, which asks the
//   person and only accepts an APK signed like the installed app.
// The private cache is emptied every time the app starts.

@InvokeArg
class PickArgs {
  var many: Boolean = false
}

@InvokeArg
class SaveArgs {
  var name: String = "file"
}

@InvokeArg
class CopyArgs {
  var path: String = ""
  var uri: String = ""
}

@InvokeArg
class InstallArgs {
  var path: String = ""
}

@InvokeArg
class RebuildArgs {
  var input: String = ""
  var output: String = ""
}

@TauriPlugin
class MediaPlugin(private val activity: Activity) : Plugin(activity) {
  private val inDir get() = File(activity.cacheDir, "sentinel-in")
  private val outDir get() = File(activity.cacheDir, "sentinel-out")

  init {
    // Leftovers from last time (picked, rebuilt or unsaved files).
    inDir.deleteRecursively()
    outDir.deleteRecursively()
  }

  private fun randomName(): String {
    val b = ByteArray(12)
    SecureRandom().nextBytes(b)
    return b.joinToString("") { "%02x".format(it) }
  }

  @Command
  fun pickFiles(invoke: Invoke) {
    val args = invoke.parseArgs(PickArgs::class.java)
    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
      addCategory(Intent.CATEGORY_OPENABLE)
      type = "*/*"
      putExtra(Intent.EXTRA_ALLOW_MULTIPLE, args.many)
    }
    startActivityForResult(invoke, intent, "picked")
  }

  @ActivityCallback
  fun picked(invoke: Invoke, result: ActivityResult) {
    val uris = mutableListOf<Uri>()
    if (result.resultCode == Activity.RESULT_OK) {
      val data = result.data
      val clip = data?.clipData
      if (clip != null) {
        for (i in 0 until clip.itemCount) uris.add(clip.getItemAt(i).uri)
      } else {
        data?.data?.let { uris.add(it) }
      }
    }
    Thread {
      val paths = JSArray()
      for (uri in uris.take(8)) {
        try {
          val dir = File(inDir, randomName()).apply { mkdirs() }
          val out = File(dir, "file")
          activity.contentResolver.openInputStream(uri)?.use { input ->
            out.outputStream().use { input.copyTo(it) }
          }
          if (out.exists()) paths.put(out.absolutePath)
        } catch (_: Exception) {
        }
      }
      val ret = JSObject()
      ret.put("paths", paths)
      invoke.resolve(ret)
    }.start()
  }

  @Command
  fun saveFile(invoke: Invoke) {
    val args = invoke.parseArgs(SaveArgs::class.java)
    val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
      addCategory(Intent.CATEGORY_OPENABLE)
      type = "application/octet-stream"
      putExtra(Intent.EXTRA_TITLE, args.name)
    }
    startActivityForResult(invoke, intent, "saveChosen")
  }

  @ActivityCallback
  fun saveChosen(invoke: Invoke, result: ActivityResult) {
    val ret = JSObject()
    val uri = if (result.resultCode == Activity.RESULT_OK) result.data?.data else null
    if (uri != null) {
      val dir = File(outDir, randomName()).apply { mkdirs() }
      ret.put("uri", uri.toString())
      ret.put("path", File(dir, "file").absolutePath)
    }
    invoke.resolve(ret)
  }

  @Command
  fun copyToUri(invoke: Invoke) {
    val args = invoke.parseArgs(CopyArgs::class.java)
    Thread {
      try {
        val src = File(args.path)
        activity.contentResolver.openOutputStream(Uri.parse(args.uri), "wt")?.use { out ->
          src.inputStream().use { it.copyTo(out) }
        }
        src.delete()
        invoke.resolve(JSObject())
      } catch (e: Exception) {
        invoke.reject(e.message ?: "couldn't save the file")
      }
    }.start()
  }

  @Command
  fun rebuildMedia(invoke: Invoke) {
    val args = invoke.parseArgs(RebuildArgs::class.java)
    // Media3 runs on a thread with a message loop (the main one); the work
    // itself happens on its own threads.
    activity.runOnUiThread {
      try {
        val transformer = Transformer.Builder(activity)
          .setVideoMimeType(MimeTypes.VIDEO_H264)
          .setAudioMimeType(MimeTypes.AUDIO_AAC)
          .addListener(object : Transformer.Listener {
            override fun onCompleted(composition: Composition, exportResult: ExportResult) {
              invoke.resolve(JSObject())
            }

            override fun onError(composition: Composition, exportResult: ExportResult, exportException: ExportException) {
              File(args.output).delete()
              invoke.reject(exportException.message ?: "couldn't rebuild the file")
            }
          })
          .build()
        // An (identity) picture effect makes Media3 decode and encode the
        // video again instead of copying it.
        val item = EditedMediaItem.Builder(MediaItem.fromUri(Uri.fromFile(File(args.input))))
          .setEffects(Effects(listOf(), listOf(MatrixTransformation { _: Long -> Matrix() })))
          .build()
        File(args.output).parentFile?.mkdirs()
        transformer.start(item, args.output)
      } catch (e: Exception) {
        invoke.reject(e.message ?: "couldn't rebuild the file")
      }
    }
  }

  private val installAction get() = activity.packageName + ".INSTALL_STATUS"
  private var receiver: BroadcastReceiver? = null

  @Command
  fun installApk(invoke: Invoke) {
    val args = invoke.parseArgs(InstallArgs::class.java)
    if (Build.VERSION.SDK_INT >= 26 && !activity.packageManager.canRequestPackageInstalls()) {
      activity.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + activity.packageName)))
      invoke.reject("Allow Sentinel to install its updates on the screen that just opened, then tap Install again.")
      return
    }
    if (receiver == null) {
      // The installer's answers: when it needs the person to confirm, show
      // its screen.
      val r = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
          if (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -999) == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            @Suppress("DEPRECATION")
            val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
            confirm?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            confirm?.let { activity.startActivity(it) }
          }
        }
      }
      ContextCompat.registerReceiver(activity, r, IntentFilter(installAction), ContextCompat.RECEIVER_NOT_EXPORTED)
      receiver = r
    }
    Thread {
      val apk = File(args.path)
      try {
        val installer = activity.packageManager.packageInstaller
        val id = installer.createSession(PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL))
        installer.openSession(id).use { session ->
          session.openWrite("sentinel.apk", 0, apk.length()).use { out ->
            apk.inputStream().use { it.copyTo(out) }
            session.fsync(out)
          }
          val status = Intent(installAction).setPackage(activity.packageName)
          val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
          session.commit(PendingIntent.getBroadcast(activity, id, status, flags).intentSender)
        }
        invoke.resolve(JSObject())
      } catch (e: Exception) {
        invoke.reject(e.message ?: "couldn't start installing the update")
      } finally {
        apk.delete()
      }
    }.start()
  }

  @Command
  fun outputPath(invoke: Invoke) {
    val dir = File(outDir, randomName()).apply { mkdirs() }
    val ret = JSObject()
    ret.put("path", File(dir, "rebuilt.mp4").absolutePath)
    invoke.resolve(ret)
  }
}
