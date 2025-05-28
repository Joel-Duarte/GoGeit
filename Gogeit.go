package main

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Global Constants + structs

const Repo_Dir = ".Gogeit"
const OBJ_Dir = Repo_Dir + "/objects"
const REFSHEADS_dir = Repo_Dir + "refs/heads"
const HEADfl = Repo_Dir + "/HEAD"
const Indexfl = Repo_Dir + "/index"

// Representation of file content
type BlobObj struct {
	Type    string `json:"type"`
	Content []byte `json:"content"`
}

// Entry within a TreeObject, points to a blob or another tree
type TreeEntry struct {
	Mode string `json:"mode"`
	Name string `json:"name"`
	Hash string `json:"hash"`
}

// Directory containing pointers to blobs and other trees
type TreeObj struct {
	Type    string      `json:"type"`
	Entries []TreeEntry `json:"entries"`
}

// Snapshot of the repo at a specific point in time
type CommitObj struct {
	Type         string    `json:"type"`
	TreeHash     string    `json:"treeHash"`
	ParentHashes []string  `json:"parentHashes"`
	Author       string    `json:"author"`
	Commiter     string    `json:"comitter"`
	Timestamp    time.Time `json:"timestamp"`
	Message      string    `json:"message"`
}

// Represents a file in staging area
type IndexEntry struct {
	FilePath     string    `json:"filePath"`
	FileHash     string    `json:"fileHash"`
	FileSize     int64     `json:"fileSize"`
	LastModified time.Time `json:"lastModified"`
}

// calculate SHA-1 hash
func CalcSHA1(data []byte) string {
	h := sha1.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Stores an object (blob, tree or commit) in the .gogeit/objects dir
// Prepend the object type and content lenght to the actual content
// Then calculate SHA-1, compresses the data, write it to a file
// Named by its hash within a sub dir based on the first two hash chars
func StoreObj(objectType string, conent []byte) (string, error) {
	//prepending
	header := []byte(fmt.Sprintf("%s %d\x00", objectType, len(conent)))
	storeCont := append(header, conent...)

	hash := CalcSHA1(storeCont)

	//make path for the object file
	objectDir := filepath.Join(OBJ_Dir, hash[:2])    //first two hex chars from hash for subdir name
	objectPath := filepath.Join(objectDir, hash[2:]) //rest of the hash for filename

	if err := os.MkdirAll(objectDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create object directory %s: %w", objectDir, err)
	}

	//write compressed conetnt to file named by the rest of the hash
	var b bytes.Buffer
	w := zlib.NewWriter(&b)

	if _, err := w.Write(storeCont); err != nil {
		return "", fmt.Errorf("failed to compress content: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("failed to close zlib writer: %w", err)
	}

	if err := os.WriteFile(objectPath, b.Bytes(), 0644); err != nil {
		return "", fmt.Errorf("failed to write object file %s: %w", objectPath, err)
	}

	return hash, nil
}

// Reads an object from .gogeit/objects given its hash
// Reconstructs the file path, read the compressed content, decompresses it
// Then parses out the obj type and the actual content
func ReadObject(hash string) (objectType string, conent []byte, err error) {
	//construct file path from hash
	objectPath := filepath.Join(OBJ_Dir, hash[:2], hash[2:])

	//check if it exists
	if _, err := os.Stat(objectPath); os.IsNotExist(err) {
		return "", nil, fmt.Errorf("Object with hash %s not found!", hash)
	}

	//read and decompress
	compressedData, err := os.ReadFile(objectPath)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to read object file %s: %w", objectPath, err)
	}

	r, err := zlib.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return "", nil, fmt.Errorf("Failed to create zlib reader: %w", err)
	}
	defer r.Close()

	decompressedData, err := io.ReadAll(r)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to decompress content: %w", err)
	}

	//parse objectType and actual content from the read data (format is "Type lenght\0content")
	nullByteIndex := bytes.IndexByte(decompressedData, '\x00')
	if nullByteIndex == -1 {
		return "", nil, fmt.Errorf("Invalid object format: null byte not found")
	}

	header := string(decompressedData[:nullByteIndex])
	parts := bytes.SplitN([]byte(header), []byte(" "), 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("Invalid object header format: %s", header)
	}

	objType := string(parts[0])

	objContent := decompressedData[nullByteIndex+1:]

	return objType, objContent, nil
}

// Write content to file, creates parent directories if they don't exist
func WriteFile(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("Failed to create dir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, content, 0644); err != nil {
		return fmt.Errorf("Failed to write file %s: %w", path, err)
	}
	return nil
}

// Read file content
func ReadFile(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file %s: %w", path, err)
	}
	return content, nil
}

func PathExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func CreateDir(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("Failed to create dir %s: %w", path, err)
	}
	return nil
}

// Determine current branch
// If it points to a ref it parses the branch name
// If it points to a commit hash, it returns the hash
func GetCurBranch() (string, error) {
	if !PathExists(HEADfl) {
		return "", fmt.Errorf("HEAD file not found! Not a git repository (or not initialized).")
	}

	headContent, err := ReadFile(HEADfl)
	if err != nil {
		return "", fmt.Errorf("failed to read HEAD file: %w", err)
	}

	headStr := strings.TrimSpace(string(headContent))

	// Check if HEAD points to a ref (e.g., "ref: refs/heads/master")
	if strings.HasPrefix(headStr, "ref: ") {
		refPath := strings.TrimPrefix(headStr, "ref: ")
		// Extract branch name
		parts := strings.Split(refPath, "/")
		if len(parts) >= 3 && parts[0] == "refs" && parts[1] == "heads" {
			return parts[2], nil // Return branch name
		}
		return "", fmt.Errorf("invalid HEAD ref format: %s", headStr)
	}

	// Otherwise, HEAD points to a commit hash (detached HEAD)
	if len(headStr) == 40 && isValidSHA1(headStr) {
		return headStr, nil // Return commit hash
	}

	return "", fmt.Errorf("unrecognized HEAD format: %s", headStr)
}

func GetBranchHeadCommitHash(branchName string) (string, error) {
	branchFilePath := filepath.Join(REFSHEADS_dir, branchName)
	if !PathExists(branchFilePath) {
		return "", fmt.Errorf("branch '%s' does not exist", branchName)
	}

	commitHashBytes, err := ReadFile(branchFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read branch file '%s': %w", branchName, err)
	}
	commitHash := strings.TrimSpace(string(commitHashBytes))

	if len(commitHash) != 40 || !isValidSHA1(commitHash) {
		return "", fmt.Errorf("invalid commit hash found for branch '%s': %s", branchName, commitHash)
	}

	return commitHash, nil
}

// Writes the commitHash to REFS_HEADS_DIR/branchName.
// This also updates the branch pointer to a new commit.
func SetBranchHeadCommitHash(branchName string, commitHash string) error {
	branchFilePath := filepath.Join(REFSHEADS_dir, branchName)

	if err := CreateDir(filepath.Dir(branchFilePath)); err != nil {
		return fmt.Errorf("failed to create branch directory: %w", err)
	}

	if err := WriteFile(branchFilePath, []byte(commitHash+"\n")); err != nil {
		return fmt.Errorf("failed to set branch '%s' head to %s: %w", branchName, commitHash, err)
	}
	return nil
}

// Reads and deserializes the INDEX_FILE content into a map.
// Using JSON for serialization/deserialization.
func ReadIndex() (map[string]IndexEntry, error) {
	indexMap := make(map[string]IndexEntry)

	if !PathExists(Indexfl) {
		return indexMap, nil
	}

	content, err := ReadFile(Indexfl)
	if err != nil {
		return nil, fmt.Errorf("failed to read index file: %w", err)
	}

	if len(content) == 0 {
		return indexMap, nil
	}

	if err := json.Unmarshal(content, &indexMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index content: %w", err)
	}
	return indexMap, nil
}

// Writes the indexMap content to INDEX_FILE. Using Json for serialization/deserialization.
func WriteIndex(indexMap map[string]IndexEntry) error {
	jsonData, err := json.MarshalIndent(indexMap, "", "  ") // Use MarshalIndent for pretty printing
	if err != nil {
		return fmt.Errorf("failed to marshal index map: %w", err)
	}

	if err := WriteFile(Indexfl, jsonData); err != nil {
		return fmt.Errorf("failed to write index file: %w", err)
	}
	return nil
}

func isValidSHA1(s string) bool {
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Search for the .gogeit directory upwards from the current directory returning the absolute path to the repository root or an error if not found.
func findRoot() (string, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %w", err)
	}

	for {
		repoPath := filepath.Join(currentDir, Repo_Dir)
		if PathExists(repoPath) {
			return currentDir, nil
		}
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir { // Reached file system root
			return "", fmt.Errorf("not a mygit repository (or any of the parent directories): %s", Repo_Dir)
		}
		currentDir = parentDir
	}
}

// ------ Git like Commands ------

// Initializes a new empty .gogeit repository.
// Creates the necessary directory structure and initializes the HEAD file.
func InitCommand() error {
	if PathExists(Repo_Dir) {
		return fmt.Errorf("repository already initialized in %s", Repo_Dir)
	}

	fmt.Printf("Initializing empty MyGit repository in %s\n", Repo_Dir)

	if err := CreateDir(OBJ_Dir); err != nil {
		return fmt.Errorf("failed to create objects directory: %w", err)
	}
	if err := CreateDir(REFSHEADS_dir); err != nil {
		return fmt.Errorf("failed to create refs/heads directory: %w", err)
	}

	if err := WriteFile(HEADfl, []byte("ref: refs/heads/master\n")); err != nil {
		return fmt.Errorf("failed to write HEAD file: %w", err)
	}

	fmt.Println("Repository initialized successfully.")
	return nil
}

// Adds file contents to the staging area (index).
func AddCommand(filePath string) error {
	repoRoot, err := findRoot()
	if err != nil {
		return err
	}

	content, err := ReadFile(filepath.Join(repoRoot, filePath))
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	blobHash, err := StoreObj("blob", content)
	if err != nil {
		return fmt.Errorf("failed to store blob for %s: %w", filePath, err)
	}

	fileInfo, err := os.Stat(filepath.Join(repoRoot, filePath))
	if err != nil {
		return fmt.Errorf("failed to get file info for %s: %w", filePath, err)
	}

	indexMap, err := ReadIndex()
	if err != nil {
		return fmt.Errorf("failed to read index: %w", err)
	}

	indexEntry := IndexEntry{
		FilePath:     filePath,
		FileHash:     blobHash,
		FileSize:     fileInfo.Size(),
		LastModified: fileInfo.ModTime(),
	}
	indexMap[filePath] = indexEntry

	if err := WriteIndex(indexMap); err != nil {
		return fmt.Errorf("failed to write index: %w", err)
	} // objectType remains "" for inference

	fmt.Printf("Added %s to the index (blob: %s)\n", filePath, blobHash)
	return nil
}

// record changes to the repository.
func CommitCommand(message string) error {
	repoRoot, err := findRoot()
	if err != nil {
		return err
	}
	_ = repoRoot //make var used

	indexMap, err := ReadIndex()
	if err != nil {
		return fmt.Errorf("failed to read index for commit: %w", err)
	}
	if len(indexMap) == 0 {
		return fmt.Errorf("nothing to commit, working tree clean")
	}

	// Recursively build tree objects for directories and return the hash of the root tree.
	treeHash, err := buildTreeFromIndex(indexMap)
	if err != nil {
		return fmt.Errorf("failed to build tree from index: %w", err)
	}

	// Determine parent commit(s)
	parentHashes := []string{}
	currentBranch, err := GetCurBranch()
	if err != nil {
		if !strings.Contains(err.Error(), "HEAD file not found") && !strings.Contains(err.Error(), "unrecognized HEAD format") {
			return fmt.Errorf("failed to get current branch: %w", err)
		}
	} else {
		if !isValidSHA1(currentBranch) {
			parentCommitHash, err := GetBranchHeadCommitHash(currentBranch)
			if err == nil { // A branch exists and points to a commit
				parentHashes = append(parentHashes, parentCommitHash)
			} else if !strings.Contains(err.Error(), "branch '"+currentBranch+"' does not exist") {
				// If branch doesn't exist, it's the first commit on that branch, no parent.
				return fmt.Errorf("failed to get head commit hash for branch %s: %w", currentBranch, err)
			}
		} else { // Detached HEAD, currentBranch is a commit hash
			parentHashes = append(parentHashes, currentBranch)
		}
	}

	// Create commit object
	author := os.Getenv("USER")
	if author == "" {
		author = "gogeit_user" // Fallback
	}
	committer := author // For simplicity, author and committer are same

	commitObj := CommitObj{
		Type:         "commit",
		TreeHash:     treeHash,
		ParentHashes: parentHashes,
		Author:       author,
		Commiter:     committer,
		Timestamp:    time.Now(),
		Message:      message,
	}

	commitContent, err := json.Marshal(commitObj)
	if err != nil {
		return fmt.Errorf("failed to marshal commit object: %w", err)
	}

	commitHash, err := StoreObj("commit", commitContent)
	if err != nil {
		return fmt.Errorf("failed to store commit object: %w", err)
	}

	// Update branch pointer
	if currentBranch != "" && !isValidSHA1(currentBranch) { // Only update if on a named branch, not detached HEAD
		if err := SetBranchHeadCommitHash(currentBranch, commitHash); err != nil {
			return fmt.Errorf("failed to update branch head for %s: %w", currentBranch, err)
		}
		fmt.Printf("[%s %s] %s\n", currentBranch, commitHash[:7], message)
	} else {
		// For detached HEAD or initial commit without an existing branch, just update HEAD
		if err := WriteFile(HEADfl, []byte(commitHash+"\n")); err != nil {
			return fmt.Errorf("failed to update HEAD to new commit: %w", err)
		}
		fmt.Printf("[detached HEAD %s] %s\n", commitHash[:7], message)
	}

	// Clear the index after commit
	if err := WriteIndex(make(map[string]IndexEntry)); err != nil {
		return fmt.Errorf("failed to clear index after commit: %w", err)
	}

	fmt.Printf("Commit successful: %s\n", commitHash)
	return nil
}

// Recursively build tree objects from the index.
// Returns the hash of the root tree object.
func buildTreeFromIndex(indexMap map[string]IndexEntry) (string, error) {

	rootEntries := make(map[string]TreeEntry)
	directories := make(map[string]map[string]IndexEntry) // For nested directories

	for path, entry := range indexMap {
		parts := strings.Split(path, string(os.PathSeparator))
		if len(parts) == 1 { // File at root level
			rootEntries[path] = TreeEntry{
				Mode: getMode(path),
				Name: path,
				Hash: entry.FileHash,
			}
		} else { // Nested path, indicates a directory
			dirName := parts[0]
			if _, ok := directories[dirName]; !ok {
				directories[dirName] = make(map[string]IndexEntry)
			}
			// Store the rest of the path for recursive processing
			directories[dirName][strings.Join(parts[1:], string(os.PathSeparator))] = entry
		}
	}

	// Process nested directories recursively
	for dirName, subEntries := range directories {
		subTreeHash, err := buildTreeFromIndex(subEntries)
		if err != nil {
			return "", fmt.Errorf("failed to build subtree for %s: %w", dirName, err)
		}
		rootEntries[dirName] = TreeEntry{
			Mode: "040000", // Mode for a directory
			Name: dirName,
			Hash: subTreeHash,
		}
	}

	// Convert map to slice and sort for consistent hashing
	sortedEntries := make([]TreeEntry, 0, len(rootEntries))
	for _, entry := range rootEntries {
		sortedEntries = append(sortedEntries, entry)
	}
	// Sort by name to ensure consistent tree hash
	// Sorts alphabetically for simplicity
	sort.Slice(sortedEntries, func(i, j int) bool {
		return sortedEntries[i].Name < sortedEntries[j].Name
	})

	// Create TreeObj
	treeObj := TreeObj{
		Type:    "tree",
		Entries: sortedEntries,
	}

	treeContent, err := json.Marshal(treeObj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal tree object: %w", err)
	}

	treeHash, err := StoreObj("tree", treeContent)
	if err != nil {
		return "", fmt.Errorf("failed to store tree object: %w", err)
	}

	return treeHash, nil
}

// Returns the file mode string
// For simplicity it assumes"100644" for all files in the index.
func getMode(filePath string) string {
	return "100644"
}

// LogCommand shows the commit history.
func LogCommand() error {
	repoRoot, err := findRoot()
	if err != nil {
		return err
	}
	_ = repoRoot //make var used

	currentHead, err := GetCurBranch()
	if err != nil {
		return fmt.Errorf("failed to get current HEAD: %w", err)
	}

	var commitHash string
	if isValidSHA1(currentHead) {
		commitHash = currentHead
	} else {
		commitHash, err = GetBranchHeadCommitHash(currentHead)
		if err != nil {
			return fmt.Errorf("failed to get commit hash for branch %s: %w", currentHead, err)
		}
	}

	if commitHash == "" {
		fmt.Println("No commits yet.")
		return nil
	}

	// Traverse commit history
	for commitHash != "" {
		_, commitContent, err := ReadObject(commitHash)
		if err != nil {
			return fmt.Errorf("failed to read commit object %s: %w", commitHash, err)
		}

		var commitObj CommitObj
		if err := json.Unmarshal(commitContent, &commitObj); err != nil {
			return fmt.Errorf("failed to unmarshal commit object %s: %w", commitHash, err)
		}

		fmt.Printf("commit %s\n", commitHash)
		fmt.Printf("Author: %s\n", commitObj.Author)
		fmt.Printf("Date:   %s\n", commitObj.Timestamp.Format(time.RFC1123Z))
		fmt.Printf("\n    %s\n\n", commitObj.Message)

		if len(commitObj.ParentHashes) > 0 {
			commitHash = commitObj.ParentHashes[0] // For simplicity, only follow the first parent
		} else {
			commitHash = ""
		}
	}
	return nil
}

// Provides content or type/size information for repository objects.
func CatFileCommand(objectType, objectHash string) error {
	_, err := findRoot()
	if err != nil {
		return err
	}

	objType, content, err := ReadObject(objectHash)
	if err != nil {
		return fmt.Errorf("failed to read object %s: %w", objectHash, err)
	}

	if objectType != "" && objectType != objType {
		return fmt.Errorf("object %s is of type %s, not %s", objectHash, objType, objectType)
	}

	fmt.Printf("Object Type: %s\n", objType)
	fmt.Printf("Object Size: %d bytes\n", len(content))

	switch objType {
	case "blob":
		fmt.Println("\n--- Blob Content ---")
		fmt.Println(string(content))
	case "tree":
		var treeObj TreeObj
		if err := json.Unmarshal(content, &treeObj); err != nil {
			return fmt.Errorf("failed to unmarshal tree object: %w", err)
		}
		fmt.Println("\n--- Tree Entries ---")
		for _, entry := range treeObj.Entries {
			fmt.Printf("%s %s %s\t%s\n", entry.Mode, entry.Hash[:7], entry.Name)
		}
	case "commit":
		var commitObj CommitObj
		if err := json.Unmarshal(content, &commitObj); err != nil {
			return fmt.Errorf("failed to unmarshal commit object: %w", err)
		}
		fmt.Println("\n--- Commit Details ---")
		fmt.Printf("Tree: %s\n", commitObj.TreeHash)
		for _, parent := range commitObj.ParentHashes {
			fmt.Printf("Parent: %s\n", parent)
		}
		fmt.Printf("Author: %s\n", commitObj.Author)
		fmt.Printf("Commiter: %s\n", commitObj.Commiter)
		fmt.Printf("Timestamp: %s\n", commitObj.Timestamp.Format(time.RFC1123Z))
		fmt.Printf("\nMessage:\n%s\n", commitObj.Message)
	default:
		fmt.Println("\n--- Raw Content (unknown type) ---")
		fmt.Println(string(content))
	}

	return nil
}

// Recursively search for a file's blob hash within a tree object.
func findBlobHashInTree(treeHash, relativePath string) (string, error) {
	_, treeContent, err := ReadObject(treeHash)
	if err != nil {
		return "", fmt.Errorf("failed to read tree object %s: %w", treeHash, err)
	}

	var treeObj TreeObj
	if err := json.Unmarshal(treeContent, &treeObj); err != nil {
		return "", fmt.Errorf("failed to unmarshal tree object %s: %w", treeHash, err)
	}

	parts := strings.SplitN(relativePath, string(os.PathSeparator), 2)
	currentName := parts[0]
	isDir := len(parts) > 1

	for _, entry := range treeObj.Entries {
		if entry.Name == currentName {
			if isDir {
				// If it's a directory entry, recursively search in the subtree
				if entry.Mode == "040000" {
					return findBlobHashInTree(entry.Hash, parts[1])
				} else {
					return "", fmt.Errorf("path component %s is a file, not a directory", currentName)
				}
			} else {
				// If it's the target file, return its hash
				if entry.Mode == "100644" || entry.Mode == "100755" { // Check file mode
					return entry.Hash, nil
				} else {
					return "", fmt.Errorf("entry %s is not a regular file", currentName)
				}
			}
		}
	}

	return "", fmt.Errorf("file '%s' not found in tree '%s'", relativePath, treeHash)
}

// Displays the content of a file from the latest commit.
func ShowCommand(filePath string) error {
	_, err := findRoot()
	if err != nil {
		return err
	}

	currentHead, err := GetCurBranch()
	if err != nil {
		return fmt.Errorf("failed to get current HEAD: %w", err)
	}

	var commitHash string
	if isValidSHA1(currentHead) {
		commitHash = currentHead
	} else {
		commitHash, err = GetBranchHeadCommitHash(currentHead)
		if err != nil {
			return fmt.Errorf("failed to get commit hash for branch %s: %w", currentHead, err)
		}
	}

	if commitHash == "" {
		return fmt.Errorf("no commits yet in the repository")
	}

	// Read the commit object to get its tree hash
	_, commitContent, err := ReadObject(commitHash)
	if err != nil {
		return fmt.Errorf("failed to read commit object %s: %w", commitHash, err)
	}

	var commitObj CommitObj
	if err := json.Unmarshal(commitContent, &commitObj); err != nil {
		return fmt.Errorf("failed to unmarshal commit object %s: %w", commitHash, err)
	}

	rootTreeHash := commitObj.TreeHash

	// Find the blob hash
	blobHash, err := findBlobHashInTree(rootTreeHash, filePath)
	if err != nil {
		return fmt.Errorf("failed to find file '%s' in commit %s: %w", filePath, commitHash[:7], err)
	}

	// Read and print the blob content
	objType, content, err := ReadObject(blobHash)
	if err != nil {
		return fmt.Errorf("failed to read blob object %s: %w", blobHash, err)
	}

	if objType != "blob" {
		return fmt.Errorf("object %s is not a blob (it's a %s)", blobHash, objType)
	}

	fmt.Println(string(content))
	return nil
}

// Prints usage information for gogeit.
func HelpCommand() {
	fmt.Println("Usage: gogeit <command> [arguments]")
	fmt.Println("\nAvailable commands:")
	fmt.Println("  init                          Initialize a new Gogeit repository.")
	fmt.Println("  add <file_path>               Add file contents to the staging area (index).")
	fmt.Println("  commit -m \"<message>\"       Record changes to the repository.")
	fmt.Println("  log                           Show the commit history.")
	fmt.Println("  Show <file>                   Show's content of a file as it appears in the latest commit")
	fmt.Println("  help                          Display this help message.")
	fmt.Println("--Advanced-----------------------------------------------------------------------------")
	fmt.Println("  cat-file <type> <object_hash> Display contents of repository objects.")
	fmt.Println("  cat-file -p <object_hash>     Print contents of repository objects (type inferred).")
}

func main() {
	if len(os.Args) < 2 {
		HelpCommand()
		os.Exit(0)
	}

	command := os.Args[1]

	switch command {
	case "init":
		if err := InitCommand(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "add":
		if len(os.Args) < 3 {
			fmt.Println("Usage: gogeit add <file_path>")
			os.Exit(1)
		}
		filePath := os.Args[2]
		if err := AddCommand(filePath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "commit":
		message := ""
		if len(os.Args) >= 3 && os.Args[2] == "-m" {
			if len(os.Args) < 4 {
				fmt.Println("Usage: gogeit commit -m \"<message>\"")
				os.Exit(1)
			}
			message = os.Args[3]
		} else {
			fmt.Println("Error: commit command requires a message. Use -m \"<message>\"")
			os.Exit(1)
		}

		if err := CommitCommand(message); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "log":
		if err := LogCommand(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "cat-file":
		if len(os.Args) < 4 {
			fmt.Println("Usage: gogeit cat-file <type> <object_hash>")
			fmt.Println("       gogeit cat-file -p <object_hash> (print, infer type)")
			os.Exit(1)
		}
		objectType := ""
		objectHash := ""

		if os.Args[2] == "-p" {
			if len(os.Args) < 4 {
				fmt.Println("Usage: gogeit cat-file -p <object_hash>")
				os.Exit(1)
			}
			objectHash = os.Args[3]
		} else {
			objectType = os.Args[2]
			objectHash = os.Args[3]
		}

		if err := CatFileCommand(objectType, objectHash); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "show":
		if len(os.Args) < 3 {
			fmt.Println("Usage: gogeit show <file_path>")
			os.Exit(1)
		}
		filePath := os.Args[2]
		if err := ShowCommand(filePath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "help":
		HelpCommand()
		os.Exit(0)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Available commands: init, add, commit, log, cat-file")
		os.Exit(1)
	}
}
