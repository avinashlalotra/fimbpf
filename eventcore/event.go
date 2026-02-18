package eventcore

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
	"watchd/bpfloader"
	"watchd/netlog"
	"watchd/preprocess"
)

func ProcessEvent(event *bpfloader.FileChangeEvent, bpf *bpfloader.BPF, policy *preprocess.Cache) (netlog.Payload, bool) {

	var payload netlog.Payload

	// if Filter returns false then only process the event
	if Filter(event, policy.FilterList) {
		return payload, false
	}

	payload.AfterSize = event.AfterSize
	payload.BeforeSize = event.BeforeSize
	payload.FileSize = event.AfterSize

	payload.CheckSum = "dummy"
	payload.Username = resolveUsername(event.Uid)
	payload.FromIp = getHostIP().String()
	payload.TimeStamp = time.Now().Format("2006-01-02 03:04:05 PM")
	payload.Tty = resolveTtyName(event.TtyMajor, event.TtyIndex)

	chngType := event.ChangeType & 0xF
	bytes := event.ChangeType >> 4

	if chngType == 1 {
		payload.ChangeType = "CREATE"
		bpf.UpdateLookupTable(event)
		updatePathCache(event, &policy.PathCache)
	} else if chngType == 3 {
		payload.ChangeType = "DELETE"
	} else if chngType == 2 {
		payload.ChangeType = fmt.Sprintf("MODIFY [%d bytes]", bytes)
	} else {
		payload.ChangeType = "UNKNOWN"
	}

	// payload.FilePath = constructPath(event, &policy.PathCache)
	payload.FilePath = preprocess.CString(event.Filename[:])

	return payload, true
}

func PrintPayload(payload netlog.Payload) {
	log.Printf("\n EventType: %s ,Filename: %s ,  Username %s, TTY : %s ,  Size : %d->%d , FromIP : %s , TimeStamp : %s \n",
		payload.ChangeType, payload.FilePath,
		payload.Username,
		payload.Tty, payload.BeforeSize, payload.AfterSize,
		payload.FromIp, payload.TimeStamp)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Update the map if a new directory is created.
func updatePathCache(event *bpfloader.FileChangeEvent, p *preprocess.PathCache) {

	key := preprocess.CacheKey{
		Inode_number: event.InodeNumber,
		Dev_id:       event.Dev,
	}

	value := preprocess.CacheValue{
		Parent: &preprocess.CacheKey{
			Inode_number: event.ParentInodeNumber,
			Dev_id:       event.ParentDev,
		},
		Filename: preprocess.CString(event.Filename[:]),
	}

	p.Put(key, value)
}

// To consturct path form a event
func constructPath(event *bpfloader.FileChangeEvent, p *preprocess.PathCache) string {

	key := preprocess.CacheKey{
		Inode_number: event.ParentInodeNumber,
		Dev_id:       event.ParentDev,
	}

	filename := preprocess.CString(event.Filename[:])
	ref, ok := p.Get(key)
	if !ok {
		log.Println("Key not found ", key)
		return filename
	}

	var path string = pfs(&ref, p)

	if path == "" {
		log.Println("Path not found ", key)
		return filename
	}

	return filepath.Join(path, filename)
}

func pfs(ref *preprocess.CacheValue, p *preprocess.PathCache) string {
	if ref == nil {
		return ""
	}

	const maxDepth = 10

	var parts []string
	current := ref

	for i := 0; i < maxDepth; i++ {
		if current == nil {
			break
		}

		parts = append(parts, current.Filename)

		if current.Parent == nil {
			break
		}

		parentKey := *current.Parent
		parentValue, ok := p.Get(parentKey)
		if !ok {
			break
		}

		current = &parentValue
	}

	// Reverse parts because we collected leaf → root
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	return "/" + strings.Join(parts, "/")
}

/*
*  resolveTtyName
@major : Major obtained from task struct in ebpf program
@index : index obtained from task struct in ebpf program
returns : "Unknown" if major not able to open /proc/tty/drivers

	: "None" if major is null or not found
	: "<name>/<index>" if major and index are found
*/
func resolveTtyName(major int32, index uint32) string {

	if major == -1 {
		return "None"
	}

	f, err := os.Open("/proc/tty/drivers")
	if err != nil {
		return "Unknown"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		ele := strings.Fields(line)

		// <name> <dev-prefix> <major> <minor-range> <type>
		if len(ele) < 5 {
			continue
		}

		if ele[2] == fmt.Sprint(major) {
			return fmt.Sprintf("%s/%d", ele[1], index)
		}
	}

	return "None"
}

/*
resolveUsername
@uid : uid obtained from task struct in ebpf program
@gid : gid obtained from task struct in ebpf program
returns : "Unknown" if unable to lookup

	: "<username>" if uid and gid are found
*/
func resolveUsername(uid uint32) string {

	u, err := user.LookupId(fmt.Sprint(uid))
	if err != nil {
		return "Unknown"
	}
	return u.Username
}

/*
// GetHostIP returns the IP address associated with the current user context.
//
// Behavior:
//   1. If the process is running under an SSH session, it returns the
//      remote SSH client IP address.
//   2. Otherwise, it returns the primary IP address of the host.
*/
func getHostIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// return False if filtered
// On false log the event and send to api
func Filter(event *bpfloader.FileChangeEvent, filterList preprocess.FilterList) bool {

	// check for extension
	file := preprocess.CString(event.Filename[:])

	ext := filepath.Ext(file)

	_, ok := filterList.IgnoredExtensions[ext]
	if ok {
		fmt.Println("Filtered by extension")
		return true
	}

	// check for suffix

	for _, suffix := range filterList.IgnoredSuffixes {
		if strings.HasSuffix(file, suffix) {
			fmt.Println("Filtered by suffix")
			return true
		}
	}

	return false

}
