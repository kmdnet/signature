// EICAR_RULE

import "hash"

rule Eicar_rule{
	meta:
		description = "Detects eicar file"
		
		author = "kmdnet"
		date = "2016/10/24"
		hash = "8a8f36de82e1278abb02f"
	
	condition:
		//hash.md5(0,filesize) == "44d88612fea8a8f36de82e1278abb02f"
		//hash.sha1(0,filesize) == "3395856ce81f2b7382dee72602f798b642f14140"
		hash.sha256(0,filesize) == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
}
