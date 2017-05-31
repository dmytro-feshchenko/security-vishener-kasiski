package main

import (
	"encoding/hex"
	"fmt"

	"github.com/technoboom/security-kasiski-hacking/helpers"
	utils "github.com/technoboom/security-kasiski-hacking/utils"
)

func encodeSample() {
	originalText := "Hello, World!"
	password := []byte{0xae, 0x80, 0x3a, 0xb3, 0xa8, 0xf5, 0xc0}
	text := []byte("Hello, World!")

	encodedText, err := utils.EncodeWithVishener(text, password)

	fmt.Println("Original text: " + originalText)
	fmt.Println("Text in bytes (hex): " + hex.EncodeToString(text[:]))
	fmt.Println("Password (hex):" + hex.EncodeToString(password))

	if err != nil {
		fmt.Println("Error: " + err.Error())
	} else {
		fmt.Println("Encoded text: " + hex.EncodeToString(encodedText[:]))
	}
}

func encodeAndDecodeSample() {
	fmt.Println("==================== Encrypt with Vishener")
	text, err := helpers.ReadFile("./lab1/sources/encrypt.txt")
	if err != nil {
		panic("Error while reading file: " + err.Error())
	}
	originalText := string(text)
	password := []byte("avgustin")

	fmt.Println("Original text: " + originalText)
	fmt.Println("Text in bytes (hex): " + hex.EncodeToString(text[:]))
	fmt.Println("Password:" + string(password))
	fmt.Println("Password (hex):" + hex.EncodeToString(password))

	encodedText, err := utils.EncodeWithVishener(text, password)
	if err != nil {
		fmt.Println("Error: " + err.Error())
	} else {
		fmt.Println("Encoded text (using XOR): " + string(encodedText[:]))
	}

	fmt.Println("\n\n==================== Decode with Kasiski")
	fmt.Printf("Encrypted text:\n%s\n\n", string(encodedText))
	decodedText, err := utils.KasiskiRun(string(encodedText))
	if err != nil {
		fmt.Println("Error: " + err.Error())
	} else {
		fmt.Println("Decrypted text: " + string(decodedText[:]))
	}
}

// use method Kasisky for decoding
func decodeSample() {
	// text := []byte{0xe6, 0xe5, 0x56, 0xdf, 0xc7, 0xd9, 0xe0,
	// 	0xd9, 0xef, 0x48, 0xdf, 0xcc, 0xd4}

}

func decodeSample2() {
	fmt.Println("\n\n==================== Kasiski method")
	bytesText, err := helpers.ReadFile("./lab1/sources/decrypt.txt")
	if err != nil {
		panic("Error while reading file: " + err.Error())
	}
	text := string(bytesText)
	// text := "UTPDHUG NYH USVKCG МУСЕ FXL KQIB. WX RKU GI TZN, RLS BHZLXMSNP KDKS; СЕВ Ш HKEWIBA, YYM SRB PER SBS, JV UPL О UVADGR HRRWXF. JV ZTVOOV УН ZCQU У UKWGEB, PL UQFB Р FOUKCG, TBF RQ VHCF R KPG, 0U КЕТ ZCQU MAW QKKW ZGSY, ЕР PGM QKETK UQEB DER EZRN, MCYE, MG UCTESVA, WP КЕТ ZCQU MAW KOIJS, LCOV NTHDNV JPNUJVB Ш GGV RWX ONKCGTHKFL XG VKD, ZJM VG CCI MVGD JPNUJ, RLS EWVKJT ASGUCS MVGD; DDK VG NYH PWUV CCHIIY RD DBQN RWTH PFRWBBI VTTK VCGNTGSF FL IAWU XJDUS, HFP VHSF, RR LAWEY QDFS RVMEES FZB СНН JRTT MVGZP UBZN FD ATIIYRTK WP КЕТ HIVJCI; TBF BLDPWPX RWTH ULAW TG VYCHX KQLJS US DCGCW OPPUPR, VG KFDNUJK GI JIKKC PL KGCJ lAOV KFTR GJFSAW KTZLZES WG RWXWT VWTL WP XPXGG, CJ EPOS VYC BTZCUW XG ZGJQ PMHTRAIBJG WMGEG. JZQ DPB JVYGM ZCLEWXR:CEB lAOV NYH JIKKC TGCWXE UHE JZK. WX VCULD YTTKETK WPKCGVCWIQT PWVY QEBFKKQ, QNH NZTTWIREL IAS VERPE ODJRXGSPTC EKWPTGEES, GMCG TTVVPLTEEJ; YCW WV NYH TZYRWH LOKU MU AWO, KEPM VG BLTP VQN RD DSGG AWKWUKKPL KGCJ, XY GPP KPG ONZTT ICUJCHLSE KET DBQHJTWUG. DYN MVCK ZT MEWCW HTWE ED JL, GPU YAE CH LQ! PGR UE, YH MWPP RXE CDJCGOSE, XMS UZGJQJL, SXVPN HBG!"
	// text := []byte(sourceText)
	fmt.Println("Encoded text:\n" + text + "\n")

	// find possible key lengths
	possibleKeyLens := utils.FindKeyLength(text)

	fmt.Println("Possible key lengths:")
	fmt.Printf("%v\n", possibleKeyLens)

	utils.KasiskiRun(text)
	decodedResult, decodingErr := utils.EncodeWithVishener(
		[]byte(text),
		[]byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x3e})
	if decodingErr != nil {
		panic(decodingErr)
	}
	fmt.Println("Decoded text:")
	fmt.Println(string(decodedResult))
}

func main() {
	// encodeSample()
	// decodeSample2()
	encodeAndDecodeSample()
}
