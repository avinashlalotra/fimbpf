package preprocess

import (
	"errors"
	"fmt"
	"syscall"
	"watchd/bpfloader"
)

type FilterList struct {
	IgnoredSuffixes   []string
	IgnoredExtensions map[string]uint8
}

type Cache struct {
	LookupTable bpfloader.TrackedFileMap
	PathCache   PathCache
	FilterList
}

func ParseConfig(configPath string) (Cache, error) {

	lookupTable, pathCache, filterList, err := parseConfig(configPath)
	if err != nil {
		return Cache{}, err
	}

	if len(lookupTable) == 0 {
		return Cache{}, errors.New("policy map is empty Please check the policy file")
	}
	return Cache{
		LookupTable: lookupTable,
		PathCache:   pathCache,
		FilterList:  filterList,
	}, nil
}

func (p *Cache) LoadTrackedFileMap(bpf *bpfloader.BPF) (int, error) {

	var count int
	var totalEntries = len(p.LookupTable)
	fmt.Println("Total entries in policy Table ", totalEntries)
	for k, v := range p.LookupTable {
		fmt.Println("Loading key ( ", k.InodeNumber, ", ", k.Dev, ")")
		if err := bpf.Objects.PolicyTable.Put(k, v); err != nil {
			fmt.Println("Error loading entry into the policy table")
			fmt.Println("Total of ", totalEntries-count, " entries not loaded")
			return count, err

		}
		count++
	}

	fmt.Println("Loaded", count, " entries into the policy table")
	return count, nil
}

/* -------------------------------------------------------------------------------------- Internal Helpers -----------------------------------*/
func parseConfig(configPath string) (bpfloader.TrackedFileMap, PathCache, FilterList, error) {

	/* For ebpf lookup table*/
	tokens, err := ReadConfig(configPath)
	if err != nil {
		return nil, PathCache{}, FilterList{}, err
	}
	if err := SyntaxValidation(tokens); err != nil {
		return nil, PathCache{}, FilterList{}, err
	}

	exlPol := parseExcludePolicy(tokens)

	filterList := FilterList{
		IgnoredSuffixes:   exlPol.excludeSuffs,
		IgnoredExtensions: exlPol.excludeExts,
	}

	ret, err := constructPolicyMap(tokens, exlPol)

	/* for Path reconstruction */
	var path_cache PathCache
	path_cache.initPathCache()
	for _, token := range tokens {
		if token.command == "D" || token.command == "IF" {
			path_cache.buildCache(token.argument)
		}
	}

	fmt.Println("Policy Map items: ", len(ret))
	fmt.Println("Policy Map Size: ", (len(ret)*17.0)/1024.0, " KB")

	fmt.Println("Path Cache items: ", len(path_cache.cache))
	fmt.Println("Path Cache Size: ", (len(path_cache.cache)*17.0)/1024.0, " KB")

	return ret, path_cache, filterList, nil

}

func (p *PathCache) initPathCache() PathCache {

	p.cache = make(map[CacheKey]CacheValue)
	p.Put(base_key, CacheValue{
		Parent:   nil,
		Filename: "",
	})

	return *p
}

/* Internal helpers */
/* Don't touch this */

func rawDev(st *syscall.Stat_t) uint64 {
	major := uint64(st.Dev >> 8)
	minor := uint64(st.Dev & 0xff)
	return (major << 20) | minor
}
