rule Stealer_Detector {
    meta:
        description = "Детектор клавиатурных шпионов и стилеров"
        author = "Konafk"
        date = "2024-04-18"
    
    strings:
        // Типичные строки для кражи данных
        $stealing_keyword = "steal_passwords" nocase wide
        $browser_data = "Chrome\\User Data\\Default\\Login Data" wide
        $clipboard_hook = "SetClipboardViewer" fullword
        
        // Методы сокрытия
        $injection_method = "VirtualAllocEx" fullword
    
    condition:
        2 of them and filesize < 1MB
}