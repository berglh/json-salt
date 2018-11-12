package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/json-iterator/go"
	"golang.org/x/crypto/ssh/terminal"
)

// NOTICE
// This program uses some modified functions from Elastic Co Beats under the Apache 2.0 License

const (
	jsonSaltVersion = "v0.2.0" // json-salt version number
)

// Job is a struct for storing hashing job payload
type Job struct {
	ID   int                    // Job Number, could be used for sorting
	Work map[string]interface{} // JSON object decoded from stream
}

// Options stores the config options for jobs
type Options struct {
	B      bool   // Brute forces hashes, no caching in map
	LC     bool   // Transforms value to lowercase before hashing
	UC     bool   // Transforms value to uppercase before hashing
	WS     bool   // Removes trailing and leading whitespace before hashing
	Pretty bool   // Outputs Pretty JSON
	File   string // Path to input file
	Output string // Path to output file
	Salt   []byte // User salt in a byte array for salted-hashing
}

// MapStr type used for the elastic JSON map walker functions
type MapStr map[string]interface{}

var wg sync.WaitGroup // WaitGroup for the go routines
var options Options   // Storing global job options
var hashmap sync.Map  // Store key value hashes to pevent doing unnessasry calculations

func main() {
	// Flags
	f := flag.String("f", "", "Path to the input json file")
	o := flag.String("o", "", "Path to the output json file")
	d := flag.String("d", ".", "Specify custom delimiter for nested key path, dot delimiter by default")
	k := flag.String("k", "", "The path to the key name to hash, separated by delimeter for nested keys")
	s := flag.String("s", "", "Salt to hash the value with")
	p := flag.Int("w", 1, "Number of concurrent processors")
	lc := flag.Bool("lc", false, "Convert key value to lowercase before hashing")
	b := flag.Bool("b", false, "Brute force just hashes every value and doesn't cache hashes to a map (typically faster)")
	uc := flag.Bool("uc", false, "Convert key value to uppercase before hashing")
	ws := flag.Bool("ws", false, "Strip trailing and leading whitespace on key value before hashing")
	pretty := flag.Bool("p", false, "Pretty print the JSON output instead of JSON lines")
	version := flag.Bool("version", false, "Print the program version")

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

	// Improvement: Need to choose upper case or lower case, not both

	// Split the key by delimiter
	keyParts := strings.Split(*k, *d)

	// Capture options from flags
	options := Options{LC: *lc, UC: *uc, WS: *ws, B: *b, File: *f, Output: *o, Pretty: *pretty}

	// If the salt isn't provided by switch, read it in
	if *s == "" {
		fmt.Fprint(os.Stderr, "Enter salt to hash with: ")
		options.Salt, _ = terminal.ReadPassword(int(syscall.Stdin)) // Prevents seeing the entered hash
		fmt.Fprintf(os.Stderr, "\r                        ")
	} else {
		options.Salt = []byte(*s) // Capture the salt flag as a byte array for consistency
	}

	jobs := make(chan *Job, 1000)  // Buffered job chann
	out := make(chan string, 1000) // Buffered output channel

	// Start consumer routines
	for i := 0; i < *p; i++ { // 5 consumers
		wg.Add(1)
		go consume(i, jobs, out, keyParts, hashmap, options)
	}

	go output(out, options)        // Start output routine
	go produce(jobs, *f, keyParts) // Start producer routine

	wg.Wait() // Wait until all routines have finished

	// Close the channels
	close(jobs)
	close(out)

}

func produce(jobs chan<- *Job, file string, keyParts []string) {

	// Open file for steraming
	jsonFile, err := os.Open(file) // Open up a file to read in bytes
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %s", err)
		os.Exit(1)
	}
	defer jsonFile.Close() // Close the file when finished

	// Set vars for decoding
	var json = jsoniter.ConfigCompatibleWithStandardLibrary // Use jsoniter instead of encoding/json
	decoder := json.NewDecoder(jsonFile)                    // Create a new JSON decoder for the JSON file
	ID := 0                                                 // Set Job ID value

	// Decoding loop
	for {
		data := make(MapStr)         // Local map string interface required for job submission
		err := decoder.Decode(&data) // Decode the next JSON document
		if err != nil {
			if err.Error() != "EOF" {
				fmt.Fprintf(os.Stderr, "\nError decoding JSON: %s", err)
				break
			}
			if err.Error() == "EOF" {
				break
			}
		}
		ID++                             // Incerement Job ID counter
		jobs <- &Job{ID: ID, Work: data} // Submit a job to the jobs channel

		if ID%1000 == 0 {
			fmt.Fprintf(os.Stderr, "\rTotal JSON docs: %d", ID) // Print our totals periodically
		}
	}

	fmt.Fprintf(os.Stderr, "\rTotal JSON docs: %d", ID) // Print the totals after parsing the file

}

func consume(id int, jobs <-chan *Job, out chan<- string, keyParts []string, hashmap sync.Map, options Options) {

	defer wg.Done() // Keep the WaitGroup open

	for job := range jobs {

		var hash interface{}              // Interface for storing md5 hash
		var json = jsoniter.ConfigFastest // Use jsoniter instead of encoding/json
		var ok bool                       // Conditional bool that gets reused in the loop

		value, err := getValue(keyParts, job.Work) // Get the value of the supplied key
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nFailed to get value %s on doc %d. Error: %v\n", keyParts, job.ID, err)
			value = ""
		} else {
			// Perform additional transformations if set
			if options.WS == true { // Clear trailing and leading whitespace on the key value
				value = strings.TrimSpace(value.(string))
			}
			if options.LC == true { // Force key value to lower case
				value = strings.ToLower(value.(string))
			}
			if options.UC == true { // Force key value to upper case
				value = strings.ToUpper(value.(string))
			}
		}

		if options.B == false {

			// Lock the hashmap for reading
			hash, ok = hashmap.Load(value)

			if !ok {
				h := md5.New()                          // Create a new md5 object
				io.WriteString(h, string(options.Salt)) // Add some salt
				io.WriteString(h, value.(string))       // Garnish with value
				hash = hex.EncodeToString(h.Sum(nil))   // get the has
				hashmap.Store(value.(string), hash)     // Capture the hash to the cache map
			}

		} else {
			h := md5.New()                          // Create a new md5 object
			io.WriteString(h, string(options.Salt)) // Add some salt
			io.WriteString(h, value.(string))       // Garnish with value
			hash = hex.EncodeToString(h.Sum(nil))   // get the has
		}

		// Update the value in the data map with the hashed value if present
		if value != "" {
			job.Work, _, err = putValue(keyParts, job.Work, hash)
		}

		// Encode for output
		if options.Pretty == false {
			// Encode JSON lines
			dataout, _ := json.MarshalToString(job.Work)
			out <- dataout // Submit encoded object to the out channel
		} else {
			// Endcode pretty JSON
			dataout, _ := json.MarshalIndent(job.Work, "", "    ")
			out <- string(dataout) // Submit encoded object to the out channel
		}

	}

}

func output(out <-chan string, options Options) {

	// Direct encoded object to output file or stdout
	if options.Output != "" {

		outFile, err := os.Create(options.Output) // Open up a file to write out
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating/opening output file: %s", err)
			os.Exit(1)
		}
		defer outFile.Close()

		w := bufio.NewWriter(outFile) // Create a new writers

		// Reading docs from out channel and write to file
		for doc := range out {
			_, err = w.WriteString(doc + "\n")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error writing to output file buffer: %s", err)
				os.Exit(1)
			}
			w.Flush()
		}
	} else {
		// Reading docs from out channel and write to stdout
		for doc := range out {
			fmt.Printf("%s\n", doc)
		}
	}
}

// Adapted & reused code from Elastic Beats to walk nested fields in an arbitrary map
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
func getValue(keyParts []string, data MapStr) (interface{}, error) {
	var err error

	o := data // A working map to store the current object

	// Walk maps until reaching a leaf object
	for _, k := range keyParts[0 : len(keyParts)-1] {
		v, exists := o[k]
		if !exists {
			return nil, fmt.Errorf("Key does not exist: %+v", k)
		}
		o, err = toMapStr(v)
		if err != nil {
			return nil, err
		}
	}
	value, found := o[keyParts[len(keyParts)-1]]
	if !found {
		return nil, fmt.Errorf("Key does not exist")
	}
	return value, nil
}

//putValue walks a map until finding the target key and returns the value
func putValue(keyParts []string, putdata MapStr, putvalue interface{}) (map[string]interface{}, interface{}, error) {
	var err error

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
