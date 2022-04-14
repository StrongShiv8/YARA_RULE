rule Text_File
{
	meta:
		Find = "I am searching for Text file with the content of Facebook in it."

	strings:
		$Finding = { D0 CF 11 E0 A1 B1 1A E1 }    /*  DOC --> D0 CF 11 E0 A1 B1 1A E1  --> Microsoft Office document   */
		$Content = "Facebook" nocase wide ascii

	condition:
		$Finding and ($Content in $Finding)
}

rule Filesize
{
	meta:
		info = "This is to check the file size"

	condition:
		filesize > 2MB

}
