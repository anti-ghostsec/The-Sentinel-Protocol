; Sentinel installer hooks (NSIS).
;
; Uninstalling with "Delete the application data" ticked also removes
; Sentinel's own data folder (encrypted identity and store, Tor state,
; encrypted media cache) and the WebView data — nothing is left behind.
; Note: on SSDs deleted files may remain recoverable at the hardware level;
; everything sensitive in these folders is encrypted at rest regardless.

!macro NSIS_HOOK_POSTUNINSTALL
  ; Disguise mode renamed the shortcuts to "Calculator": remove those too
  ; (only when Sentinel's disguise setting shows they are ours).
  ${If} ${FileExists} "$LOCALAPPDATA\sentinel-proto\app\look.json"
    Delete "$SMPROGRAMS\Calculator.lnk"
    Delete "$DESKTOP\Calculator.lnk"
  ${EndIf}
  ${If} $DeleteAppDataCheckboxState = 1
    RMDir /r "$LOCALAPPDATA\sentinel-proto"
    RMDir /r "$LOCALAPPDATA\protocol.sentinel.app"
  ${EndIf}
!macroend
