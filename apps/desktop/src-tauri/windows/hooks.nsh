; VoidWire NSIS installer hooks (Tauri v2 `bundle.windows.nsis.installerHooks`).
;
; The installer runs per-machine (elevated), so the bundled daemon can register
; itself directly. `voidwired install` copies itself and wintun.dll to a stable
; location, registers + starts the Windows service and writes the IPC token.

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Installing the VoidWire service (voidwired)..."
  nsExec::ExecToLog '"$INSTDIR\voidwired.exe" install'
  Pop $0
  IntCmp $0 0 +2 0 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "The VoidWire service could not be installed (exit code $0). Open VoidWire and use 'Install VoidWire service' to retry." /SD IDOK
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Removing the VoidWire service (voidwired)..."
  nsExec::ExecToLog '"$INSTDIR\voidwired.exe" uninstall'
  Pop $0
!macroend
