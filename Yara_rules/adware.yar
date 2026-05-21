rule Adware_Popup {
    meta:
        description = "Детектор рекламных программ и всплывающих окон"
        author = "Konafk"
        date = "2024-04-18"
    
    strings:
        // Типичные домены рекламы
        $ad_domain = ".popups.advertising-site.com" nocase wide
        $redirect_url = "http://ads.example.net/?click_id=" wide
        
        // Методы показа рекламы
        $popup_create = "ShellExecute(NULL,L\"open\",L\"" wide
        $browser_inject = "IEFrame.dll" fullword
    
    condition:
        2 of them and filesize < 2MB
}