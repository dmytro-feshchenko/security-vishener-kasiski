package utils

import (
	"fmt"
	"math"
	"sort"
	"strconv"

	configs "github.com/technoboom/security-kasiski-hacking/configs"
	helpers "github.com/technoboom/security-kasiski-hacking/helpers"
)

//Func to implement Euclid Algo
func gcd(x, y int) int {
	for y != 0 {
		x, y = y, x%y
	}
	return x
}

// NodStruct - contains position (len of key) and count of position repeats
type NodStruct struct {
	Pos   int
	Count int
}

// Nods - array of NodStruct for sorting
type Nods []NodStruct

// Len - calculates length of the Nods structure
func (slice Nods) Len() int {
	return len(slice)
}

// Less - sorts Nods by Count of repeats
func (slice Nods) Less(i, j int) bool {
	return slice[i].Count > slice[j].Count
}

// Swap - change Nods order
func (slice Nods) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// FindKeyLength - find possible key lengths for encoded text
func FindKeyLength(text string) []int {
	repeats := make([]int, 0, 10000)
	digramLength := 3
	// get through text
	for i := 0; i < len(text)-digramLength+1; i++ {
		// for each possible key len build sample with corresponding symbols
		originalPair := text[i : i+digramLength]
		for j := i + 1; j < len(text)-digramLength+1; j++ {
			tmpPair := text[j : j+digramLength]
			if originalPair == tmpPair {
				repeats = helpers.Extend(repeats, j-i)
			}
		}
	}

	nods := make([]int, 1000)
	for i := 0; i < len(repeats); i++ {
		for j := i + 1; j < len(repeats); j++ {
			nods[gcd(repeats[i], repeats[j])]++
		}
	}

	nodsCollection := make(Nods, len(nods))
	for i := 0; i < len(nods); i++ {
		nodsCollection[i] = NodStruct{Pos: i, Count: nods[i]}
	}
	sort.Sort(nodsCollection)
	lensLimit := len(nodsCollection)
	if len(nodsCollection) > 5 {
		lensLimit = 5
	}
	// create new array for storing possible lengths of the key
	lens := make([]int, lensLimit)
	for i := 0; i < lensLimit; i++ {
		lens[i] = nodsCollection[i].Pos
	}

	return lens
}

// KeyByteFrequency - stores frequensy for byte-candidate
type KeyByteFrequency struct {
	Code         int
	FrequencySum float64
}

// KasiskiFindKeyByLen - find key value with known key length
func kasiskiFindKeyByLen(text string, keyLen int) string {
	// var currentFrequencySum float64
	fmt.Println("======> Search key process is up:")
	key := ""
	initialTextFrequencySum := FrequencyAnalysisEng(text)
	fmt.Println("Initial frequensy checksum: " + strconv.FormatFloat(initialTextFrequencySum, 'f', 6, 64))
	fmt.Print("Key search start:")
	// loop for opening key step by step (symbol by symbol)
	var candidat KeyByteFrequency
	for i := 0; i < keyLen; i++ {
		// iterate over bytes
		for j := 0; j < 256; j++ {
			// use xor operation
			xorText := XorItemsWithPeriod(text, byte(j), i, keyLen)
			frequencySum := FrequencyAnalysisEng(xorText)
			// check for first iteration or min frequency sum
			if j == 0 || candidat.FrequencySum > frequencySum {
				candidat = KeyByteFrequency{
					Code:         j,
					FrequencySum: frequencySum,
				}
			}
		}
		fmt.Printf("\n#%s: %s ", strconv.Itoa(i), string(candidat.Code))
		key += string(candidat.Code)
	}
	fmt.Print("\n")
	return key
}

// FrequencyAnalysisEng - make frequency analysis of the text
func FrequencyAnalysisEng(text string) float64 {
	var sum float64
	var symbol byte
	textLen := len(text)
	frequencys := make([]int, 256)
	for i := 0; i < textLen; i++ {
		symbol = byte(text[i])
		frequencys[symbol]++
	}
	sum = 0
	for letter, frequency := range frequencys {
		letterNaturalFrequency, ok := configs.FrequencysMapEng[string(letter)]
		if ok {
			letterCalculatedFrequency := float64(frequency) / float64(textLen) * 100
			sum += math.Pow(letterCalculatedFrequency-letterNaturalFrequency, float64(2)) / letterNaturalFrequency
		}
	}
	return sum
}

// KasiskiRun - run Kasiski method to decrypt text
func KasiskiRun(text string) (string, error) {
	possibleKeyLengts := FindKeyLength(text)
	fmt.Printf("Found the most possible key lengths: %v\n", possibleKeyLengts)

	keyLen := 8
	key := kasiskiFindKeyByLen(text, keyLen)
	fmt.Println("Key found: " + key)
	decryptedText, err := EncodeWithVishener([]byte(text), []byte(key))
	if err != nil {
		panic(err)
	}
	return string(decryptedText), nil
}

// XorItemsWithPeriod - use XOR for text with certain letter with period
func XorItemsWithPeriod(text string, letter byte, startFrom int, period int) string {
	result := []byte(text[:])
	textLen := len(result)
	for i := startFrom; i < textLen; i += period {
		result[i] = result[i] ^ letter
	}
	return string(result)
}
