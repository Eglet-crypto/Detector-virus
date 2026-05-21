rule Trojan_Backdoor {
    meta:
        description = "Общий детектор бэкдоров и троянов"
        author = "Konafk"
        date = "2024-04-18"
    
    strings:
        // Типичные команды управления
        $cmd_exec = "cmd.exe /c" wide
        $reverse_shell = "nc -lvp" wide
        
        // Скрытие активности
        $hide_window = "ShowWindow(SW_HIDE)" fullword
        $registry_hide = "RegDeleteValue(HKEY_CURRENT_USER," nocase
    
    condition:
        2 of them and filesize < 500KB
}