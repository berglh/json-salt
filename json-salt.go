package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// NOTICE
// This program uses some modified functions from Elastic Co Beats under the Apache 2.0 License

const (
	jsonSaltVersion = "v0.1.0" // json-salt version number
)

// MapStr is just basic type for map[string]interface to store the JSON payloads for hashing
type MapStr map[string]interface{}

var data MapStr     // Define a working var for MapStr
var byteSalt []byte // Create a byte array to store the hash salt

// Reused code from Elastic Beats to walk nested fields in an arbitrary map
// Ref: https://github.com/elastic/beats/blob/master/libbeat/common/mapstr.go

// toMapStr ensures the type is set to MapStr during the map walk for consistency
func toMapStr(v interface{}) (MapStr, error) {
	switch v.(type) {
	case MapStr:
		return v.(MapStr), nil
	case map[string]interface{}:
		m := v.(map[string]interface{})
		return MapStr(m), nil
	default:
		return nil, fmt.Errorf("expected map but type is %T", v)
	}
}

// getValue walks a map until finding the target key and returns it's value
func getValue(key string, delim string, data MapStr) (interface{}, error) {
	var err error
	// I should probably split the keyparts outside to prevent doing this operation all the time
	keyParts := strings.Split(key, delim) // Split the key by delimiter
	m := data                             // A working map to store the current walk layer

	// Walk maps until reaching a leaf object
	for _, k := range keyParts[0 : len(keyParts)-1] {
		v, exists := m[k]
		if !exists {
			return nil, fmt.Errorf("Key does not exist: %+v", k)
		}
		m, err = toMapStr(v)
		if err != nil {
			return nil, err
		}
	}
	value, found := m[keyParts[len(keyParts)-1]]
	if !found {
		return nil, fmt.Errorf("Key does not exist")
	}
	return value, nil
}

//putValue walks a map until finding the target key and returns the value
func putValue(putkey string, delim string, putdata MapStr, putvalue interface{}) (map[string]interface{}, interface{}, error) {
	var err error
	// I should probably split the keyparts outside to prevent doing this operation all the time
	keyParts := strings.Split(putkey, delim)                // Split the key by delimiter
	expMap := make([]map[string]interface{}, len(keyParts)) // Store each step layer for reconstruction
	target := keyParts[len(keyParts)-1]                     // The target key name
	m := putdata                                            // A working map to store the current walk layer
	expMap[0] = putdata                                     // Populate the array level with the original data

	// For the range of key parts, walk the working map until the target key is hit
	for i, k := range keyParts[0 : len(keyParts)-1] {
		v, exists := m[k]
		if !exists {
			return nil, nil, fmt.Errorf("Key does not exist %s", k)
		}
		m, err = toMapStr(v) // Update m to the next step in the map
		expMap[i+1] = m      // Progressively "caching" each step
		if err != nil {
			return nil, nil, err
		}
	}
	updated, _ := m[target] // Capture the original value incase we want it later
	m[target] = putvalue    // Update the key with new value
	c := 0                  // A counter to orchestrate the map reconstruction

	// Reconstruct the original map by walking back the way we came
	// Improve: This seems kind of wasteful of cpu/memory, maybe there is a better way
	// Test: Single level hashes as well, not sure how this will pan out
	for i := len(keyParts) - 2; i >= 0; i-- {
		k := keyParts[i]
		if c == 0 {
			expMap[i][k] = m
		} else {
			expMap[i] = expMap[i+1]
		}
		c++
	}

	// Finally, populate putdata the original map with the updated inner map
	putdata[keyParts[0]] = expMap[0]
	return putdata, updated, nil
}

func main() {
	// Import flags
	f := flag.String("f", "", "Path to the input json file")
	d := flag.String("d", ".", "Specify custom delimiter for nested key path, dot delimiter by default")
	k := flag.String("k", "", "The path to the key name to hash, separated by delimeter for nested keys")
	s := flag.String("s", "", "Salt to hash the value with")
	lc := flag.Bool("lc", false, "Convert key value to lowercase before hashing")
	uc := flag.Bool("uc", false, "Convert key value to uppercase before hashing")
	w := flag.Bool("w", false, "Strip trailing and leading whitespace on key value before hashing")
	pretty := flag.Bool("p", false, "Pretty print the JSON output instead of JSON lines")
	version := flag.Bool("version", false, "Print the program version")
	//o := flag.String("o", "", "Path to the output json file") // Improve: Integrate file out later
	flag.Parse()

	// Print version and exit
	if *version == true {
		fmt.Fprintf(os.Stderr, "json-salt %s\n", jsonSaltVersion)
		os.Exit(0)
	}

	// Check the key path flag
	if *k == "" {
		fmt.Fprintf(os.Stderr, "No target key to hash defined in flag \"-k\"\n")
		os.Exit(1)
	}

	key := *k // Assign key. Improve: spli this outisde the put and get value functions

	// If the salt isn't provided by switch, read it in
	if *s == "" {
		fmt.Fprint(os.Stderr, "Enter salt to hash with: ")
		byteSalt, _ = terminal.ReadPassword(int(syscall.Stdin)) // Prevents seeing the entered hash
		fmt.Fprintf(os.Stderr, "\r                        ")
	} else {
		byteSalt = []byte(*s) // Capture the salt flag as a byte array for consistency
	}

	// Open up a reader to parse the file
	jsonFile, err := os.Open(*f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %s", err)
		os.Exit(1)
	}

	defer jsonFile.Close()               // Defer closing the JSON file
	decoder := json.NewDecoder(jsonFile) // Create a new JSON decoder for the JSON file
	hashmap := make(map[string]string)   // Store key value hashes to pevent doing unnessasry calculations
	total := 0                           // Initiate a counter to track progresss

	// Loop to decode the JSON file in a stream
	for {

		err := decoder.Decode(&data) // Decode the next JSON document
		if err != nil {              // If error decoding, end loop and provide error if relevant
			if err.Error() != "EOF" {
				fmt.Fprintf(os.Stderr, "Error decoding JSON: %s", err)
				break
			}
			if err.Error() == "EOF" {
				break
			}
		}

		// Get the value of the supplied key, season and hash
		value, err := getValue(key, *d, data)

		if err != nil {
			fmt.Fprintf(os.Stderr, "\nFailed to get value %s on doc %d. Error: %v\n", key, total+1, err)
			value = ""
		} else {
			if *w == true { // Clear trailing and leading whitespace on the key value
				value = strings.TrimSpace(value.(string))
			}
			if *lc == true { // Force key value to lower case
				value = strings.ToLower(value.(string))
			}
			if *uc == true { // Force key value to upper case
				value = strings.ToUpper(value.(string))
			}
			if _, ok := hashmap[value.(string)]; !ok {
				h := md5.New()                                           // Create a new md5 object
				io.WriteString(h, string(byteSalt))                      // Add some salt
				io.WriteString(h, value.(string))                        // Garnish with value
				hashmap[value.(string)] = hex.EncodeToString(h.Sum(nil)) // Capture the hash to the cache map
			}
		}

		// Update the value in the data map with the hashed value if present
		if value != "" {
			data, _, err = putValue(key, *d, data, hashmap[value.(string)])
		}

		if *pretty == false {
			// Print JSON lines
			dataout, _ := json.Marshal(data)
			fmt.Printf("%s\n", dataout)
		} else {
			// Print pretty JSON, so pretty
			dataout, _ := json.MarshalIndent(data, "", "    ")
			fmt.Printf("%s\n", dataout)
		}

		total++ // Track our progress
		if total%100 == 0 {
			fmt.Fprintf(os.Stderr, "\rTotal JSON docs: %d", total) // Print our totals every 100 docs
		}
	}

	jsonFile.Close() // Close that file, we're good people here

	fmt.Fprintf(os.Stderr, "\rTotal JSON docs: %d \n", total) // Return the final count

}
