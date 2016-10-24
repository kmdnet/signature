// EICAR_RULE              
                                                                      
rule Eicar_rule{                                                      
    meta:                                                             
        description = "Detects eicar file"                            
                                                                      
        author = "kmdnet"                                             
        date = "2016/10/24"                                           
        hash = "8a8f36de82e1278abb02f"                                
                                                                      
    strings:                                                          
        $string = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"                
        $hex_string = {58 35 4f 21}                                   
        $re_hex = {58 35 (4f 21 | 11 11) 50 25}                       
    condition:                                                        
        $string and $hex_string or $re_hex                            
} 