rm encrypted-output
rm iv-hex
rm pub-key
rm CA4005Assignment01.zip

javac CA4005Assignment01.java

zip -r ./CA4005Assignment01.zip CA4005Assignment01.java 
java CA4005Assignment01 CA4005Assignment01.zip

