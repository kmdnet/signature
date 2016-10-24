// pisloader

import "pe"

rule pisloader_rule{
	meta:
		description = "Detects pisloader file"
		
		author = "kmdnet"
		date = "2016/10/24"
		hash = "7b24d17e5f29e27b1c17127839be591a"
	
	condition:
		pe.imphash() == "53f7d489c21079f3039817feb1b0a825"
}
