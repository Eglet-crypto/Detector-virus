rule Generic_CoinMiner {
    meta:
        description = "Общий детектор криптовалютных майнеров"
        author = "Konafk"
        date = "2024-04-18"
    
    strings:
        // Ключевые строки, характерные для майнинговых программ
        $mining_pool = "pool.miningsite.com" nocase wide
        $wallet_addr = "1BitcoinAddressExample" nocase wide
        $mining_cmd = "/usr/local/bin/minerd" fullword
        
        // Характерные API-вызовы
        $api_call = "GetProcAddress(\"CreateRemoteThread\")" fullword
    
    condition:
        uint16(0) == 0x5A4D and ( // Проверка заголовка PE-файла
            2 of ($mining_pool, $wallet_addr, $mining_cmd, $api_call)
        )
}