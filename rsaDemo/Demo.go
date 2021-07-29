package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func GeneratePrivatekey(keysize int) {
	//1.使用rsa中的GenerateKey方法生成私钥
	privatekey, err := rsa.GenerateKey(rand.Reader, keysize)
	if err != nil {
		panic(err)
	}
	//2. 通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	derText := x509.MarshalPKCS1PrivateKey(privatekey)

	//3. 将私钥字符串设置到pem格式块中
	block := pem.Block{
		Type:  "rsa privatekey",
		Bytes: derText,
	}

	file, err := os.Create("privatekey.pem")
	if err != nil {
		panic(err)
	}
	//4. 通过pem将设置好的数据进行编码, 并写入磁盘文件中
	err = pem.Encode(file, &block)
	if err != nil {
		panic(err)
	}

	//1. 从得到的私钥对象中将公钥信息取出
	pubkey := privatekey.PublicKey
	//2. 通过x509标准将得到 的rsa公钥序列化为字符串
	derStream, err := x509.MarshalPKIXPublicKey(&pubkey)
	if err != nil {
		panic(err)
	}
	//3. 将公钥字符串设置到pem格式块中
	block = pem.Block{
		Type:  "rsa pubkey",
		Bytes: derStream,
	}
	//4. 通过pem将设置好的数据进行编码, 并写入磁盘文件
	newfile, _ := os.Create("pubkey.pem")
	pem.Encode(newfile, &block)

	defer file.Close()
	defer newfile.Close()

}

func encryerRsa(plainText []byte, filename string) []byte {
	//1.read file
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	fileinfo, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buff := make([]byte, fileinfo.Size())
	_, err = file.Read(buff)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	//2.decode from pem
	block, _ := pem.Decode(buff)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	publickey := pub.(*rsa.PublicKey)

	//3 use pk to encrypter
	entryText, err := rsa.EncryptPKCS1v15(rand.Reader, publickey, plainText)
	if err != nil {
		panic(err)
	}
	return entryText
}

func decryerRsa(entryText []byte, filename string) []byte {
	//1.read file
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	fileinfo, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buff := make([]byte, fileinfo.Size())
	_, err = file.Read(buff)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	//2.decode from pem
	block, _ := pem.Decode(buff)
	privatekey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	//3 use pk to encrypter
	decryptText, err := rsa.DecryptPKCS1v15(rand.Reader, privatekey, entryText)
	if err != nil {
		panic(err)
	}
	return decryptText
}
func main() {
	GeneratePrivatekey(1024)
	src := []byte("hello world ")
	encryText := encryerRsa(src, "pubkey.pem")
	srcText := decryerRsa(encryText, "privatekey.pem")
	fmt.Println(string(srcText))
}
