; ITriage's NSIS installer hooks (bundle > windows > nsis > installerHooks).
;
; Register the "itriage" Application event log source at install time, so
; the audit trail's events render cleanly in Event Viewer (and in WEF/SIEM)
; from the first run, even one that never runs elevated. The message file is
; .NET Framework's EventLogMessages.dll, which every supported Windows has;
; it's what PowerShell's New-EventLog uses, and what an elevated ITriage run
; registers itself when the source is missing.
;
; The source is left in place on uninstall on purpose: removing it would
; leave the events already in the log unreadable.

!macro NSIS_HOOK_POSTINSTALL
  WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\itriage" "EventMessageFile" "%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll"
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\itriage" "TypesSupported" 7
!macroend
