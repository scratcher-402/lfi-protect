package main
import (
	"os"
	"path/filepath"
	"slices"
	"io"
	"fmt"
	"sync"
	"bytes"
)

type TrieNode struct {
	To [](*TrieNode)
	Term *TrieTerm
}

type TrieTerm struct {
	Files []string
}

type Trie struct {
	Root *TrieNode
	Files []string
	Config *FilesConfig
	Walker *TrieWalker
	Mutex sync.RWMutex
	Logger *Logger
}

type TrieWalker struct {
	Trie *Trie
	Root *TrieNode
	Current *TrieNode
	Parent *TrieNode
	Depth int
}

func NewNode() *TrieNode {
	to := make([]*TrieNode, 0, 16)
	for i := 0; i < 16; i++ {
		to = append(to, nil)
	}
	return &TrieNode{To: to}
}

func NewTrie(config *FilesConfig, logger *Logger) *Trie {
	root := NewNode()
	trie := &Trie{Root: root, Files: []string{}, Config: config, Logger: logger}
	trie.Walker = NewWalkerFromTrie(trie)
	return trie
}

func NewWalker(root *TrieNode) *TrieWalker {
	return &TrieWalker{Root: root, Current: root}
}
func NewWalkerFromTrie(t *Trie) *TrieWalker {
	return &TrieWalker{Root: t.Root, Current: t.Root, Trie: t}
}

func (tw *TrieWalker) Go(index int) {
	next := tw.Current.To[index]
	if next == nil {
		// fmt.Println("[trie walker] no way, returning home")
		tw.Home()
		return
	}
	tw.Parent = tw.Current
	tw.Current = next
	tw.Depth++
	// fmt.Printf("Moved by index %d to depth %d\n", index, tw.Depth)
}
func (tw *TrieWalker) Push(index int) {
	next := tw.Current.To[index]
	if next == nil {
		next = NewNode()
		tw.Current.To[index] = next
	}
	tw.Parent = tw.Current
	tw.Current = next
	tw.Depth++
}
func (tw *TrieWalker) Home() {
	tw.Current = tw.Root
	tw.Parent = nil
	tw.Depth = 0
}

func (tw *TrieWalker) AddTermFile(path string) {
	term := tw.Current.Term
	if term == nil {
		term = &TrieTerm{}
		tw.Current.Term = term
	}
	if !slices.Contains(term.Files, path) {
		term.Files = append(term.Files, path)
	}
	if tw.Trie != nil {
		if !slices.Contains(tw.Trie.Files, path) {
			tw.Trie.Files = append(tw.Trie.Files, path)
		}
	}
}

func (t *Trie) Setup() error {
	t.Logger.Event(LOG_INFO, "trie", "Setting up trie")
	var err error
	for _, path := range t.Config.Paths {
		err = t.addFile(path)
		if err != nil {
			return err
		}
	}
	t.Logger.Event(LOG_INFO, "trie", fmt.Sprintf("Trie built successfully, %d files added", len(t.Files)))
	return err
}
func (t *Trie) addFile (path string) error {
	check := true
	for _, pattern := range t.Config.Exclude {
		match, err := filepath.Match(pattern, path)
		if err != nil {
			return err
		}
		if match {
			check = false
			break
		}
	}
	if !check {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
//		t.Logger.Event(LOG_DEBUG, "trie", "Path "+path+" is a directory")
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			subpath := entry.Name()
			if subpath == "." || subpath == ".." {
				continue
			}
			fullpath := filepath.Join(path, subpath)
			err = t.addFile(fullpath)
			if err != nil {
				return err
			}
		}
	} else {
//		t.Logger.Event(LOG_DEBUG, "trie", "Path "+path+" is a file")
		size := int(info.Size())
		if size < 160 {
			t.Logger.Event(LOG_DEBUG, "trie", fmt.Sprintf("Ignoring %s, too small (%d bytes)\n", path, size))
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		block := make([]byte, 16)
		tw := t.Walker
		tw.Home()
		var blockHash int
		for {
			n, err := file.Read(block)
			if n == 16 {
				blockHash = smallBlockHash(block)
				tw.Push(blockHash)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if tw.Depth >= 64 {
				break
			}
		}
		tw.AddTermFile(path)
		t.Logger.Event(LOG_DEBUG, "trie", fmt.Sprintf("Added %s, %d blocks\n", path, tw.Depth))
	}
	return nil
}
func (t *Trie) AnalyzeBytes(data *[]byte) error {
	result := make(chan error, 16)
	for shift := 0; shift < 16; shift++ {
		go t.analyzeBytesWithShift(data, shift, result)
	}
	count := 0
	var shiftResult error
	for {
		shiftResult = <-result
		if shiftResult != nil {
			return shiftResult
		}
		count++
		if count == 16 {
			break
		}
	}
	return nil
}
func (t *Trie) analyzeBytesWithShift(data *[]byte, shift int, result chan error) {
	fmt.Println("Analyzing bytes with shift", shift)
	t.Mutex.RLock()
	defer t.Mutex.RUnlock()
	walker := NewWalkerFromTrie(t)
	reader := bytes.NewReader(*data)
	reader.Seek(int64(shift), io.SeekCurrent)
	block := make([]byte, 16)
	var blockHash int
	var n int
	var err error
	var offset int
	for {
		n, err = reader.Read(block)
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}
		offset += n
		if n == 16 {
			blockHash = smallBlockHash(block)
			walker.Go(blockHash)
			if walker.Depth >= 9 {
				fmt.Printf("File leak detected with shift %d\n", shift)
				err = fmt.Errorf("LFI file leak detected with shift %d, depth %d, offset %d", shift, walker.Depth, offset)
				break
			}
		} else {
			err = nil
			break
		}
	}
	fmt.Println("Analysis finished with shift", shift)
	result <- err
}

func smallBlockHash(data []byte) int {
	mult := 1
	result := 5
	for _, d := range data {
		result = (result + int(d)*mult) % 16
		mult = (mult*7) % 16
	}
	return result
}
 
