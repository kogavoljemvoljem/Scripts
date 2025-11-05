SetTitleMatchMode, 2
Muted := False ; Flag to check if Discord has been muted already

Loop {
    WinGetTitle, Title, A
    If InStr(Title, "Discord") {
        ; Only send the mute shortcut if it hasn't been done already
        If (!Muted) {
            Send ^+m
            Muted := True  ; Set flag to True after muting
        }
    }
    Sleep 1000  ; Check every second
}
