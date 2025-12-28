package main
import (
	"os"
	"path/filepath"
	"slices"
	"io"
	"fmt"
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
}

type TrieWalker struct {
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

func NewTrie(config *FilesConfig) *Trie {
	root := NewNode()
	return &Trie{Root: root, Files: []string{}, Config: config, Walker: NewWalker(root)}
}

func NewWalker(root *TrieNode) *TrieWalker {
	return &TrieWalker{Root: root, Current: root}
}
func NewWalkerFromTrie(t *Trie) *TrieWalker {
	return &TrieWalker{Root: t.Root, Current: t.Root}
}

func (tw *TrieWalker) Go(index int) {
	next := tw.Current.To[index]
	if next == nil {
		tw.Home()
		return
	}
	tw.Parent = tw.Current
	tw.Current = next
	tw.Depth++
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
}

func (t *Trie) Setup() error {
	var err error
	for _, path := range t.Config.Paths {
		err = t.addFile(path)
		if err != nil {
			return err
		}
	}
	return err
}
func (t *Trie) addFile (path string) error {
	fmt.Println("Adding file", path)
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
		fmt.Println("It's a directory")
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
		fmt.Println("It's a file")
		size := int(info.Size())
		if size < 160 {
			fmt.Printf("Ignoring %s, too small (%d bytes)\n", path, size)
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
		fmt.Printf("Added %s, %d blocks\n", path, tw.Depth)
	}
	return nil
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
