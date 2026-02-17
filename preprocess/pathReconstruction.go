/** Maintain a Cache of (inode_num , dev id ) -->> (filename , parent node)   */
package preprocess

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type CacheKey struct {
	Inode_number uint64
	Dev_id       uint64
}

type CacheValue struct {
	Parent   *CacheKey
	Filename string
}

type PathCache struct {
	cache map[CacheKey]CacheValue
}

func (p *PathCache) Get(key CacheKey) (CacheValue, bool) {
	value, ok := p.cache[key]
	return value, ok
}

func (p *PathCache) Put(key CacheKey, value CacheValue) {
	p.cache[key] = value
}

func (p *PathCache) Delete(key CacheKey) {
	delete(p.cache, key)
}

func (p *PathCache) Contains(key CacheKey) bool {
	_, ok := p.cache[key]
	return ok

}

// / Path Map
var base_key = CacheKey{
	Inode_number: 0,
	Dev_id:       0,
}

// //////////---------------------- Internal helpers --------------------------------------------------////
func CString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// BuildCache will build the path cache for the given folderpath recursively
func (p *PathCache) buildCache(folderpath string) {

	// make current dir as parent of subfolders
	// process current folder

	info, err := os.Stat(folderpath)
	if err != nil {
		fmt.Printf("WARN : %v\n", err)
		return
	}

	if !info.IsDir() {
		fmt.Printf("WARN : %v is not a directory\n", folderpath)
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		fmt.Printf("WARN : %v\n", err)
		return
	}
	key := CacheKey{
		Inode_number: uint64(stat.Ino),
		Dev_id:       rawDev(stat),
	}
	if _, ok := p.cache[key]; ok {
		return
	}

	p.cache[key] = CacheValue{
		Parent:   &base_key, // parent is the parent of the current folder
		Filename: folderpath,
	}

	//log.Println("Building cache for", folderpath, "Key : (", key.inode_number, ",", key.dev_id, ")", "Value : (", p.cache[key].parent.inode_number, ",", p.cache[key].parent.dev_id, ",", p.cache[key].filename, ")")

	// process subfolders
	entries, err := os.ReadDir(folderpath)
	if err != nil {
		fmt.Printf("WARN : %v\n", err)
		return
	}
	for _, entry := range entries {
		p.__buildcache(filepath.Join(folderpath, entry.Name()), &key)
	}

}

func (p *PathCache) __buildcache(folderpath string, parent *CacheKey) {

	info, err := os.Stat(folderpath)
	if err != nil {
		fmt.Printf("WARN : %v\n", err)
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		fmt.Printf("WARN : %v\n", err)
		return
	}
	key := CacheKey{
		Inode_number: uint64(stat.Ino),
		Dev_id:       rawDev(stat),
	}
	if _, ok := p.cache[key]; ok {
		return
	}

	p.cache[key] = CacheValue{
		Parent:   parent,
		Filename: info.Name(),
	}

	//log.Println("Building cache for", folderpath, "Key : (", key.inode_number, ",", key.dev_id, ")", "Value : (", p.cache[key].parent.inode_number, ",", p.cache[key].parent.dev_id, ",", p.cache[key].filename, ")")

	if info.IsDir() {

		entries, err := os.ReadDir(folderpath)
		if err != nil {
			fmt.Printf("WARN : %v\n", err)
			return
		}
		for _, entry := range entries {
			p.__buildcache(filepath.Join(folderpath, entry.Name()), &key)
		}
	}
}
