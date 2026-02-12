package eventcore

import (
	"bufio"
	"fimbpf/bpfloader"
	"fimbpf/netlog"
	"fimbpf/preprocess"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

func ProcessEvent(event *bpfloader.FileChangeEvent, bpf *bpfloader.BPF, policy *preprocess.Cache) netlog.Payload {

	var payload netlog.Payload

	payload.AfterSize = event.AfterSize
	payload.BeforeSize = event.BeforeSize
	payload.FileSize = event.FileSize

	payload.CheckSum = "dummy"
	payload.Username = resolveUsername(event.Uid, event.Gid)
	payload.FromIp = getHostIP().String()
	payload.TimeStamp = convertMtimeToISO(event.Mtime)
	payload.Tty = resolveTtyName(event.TtyMajor, event.TtyIndex)

	if event.ChangeType == 1 {
		payload.ChangeType = "CREATE"
		bpf.UpdateLookupTable(event)
		updatePathCache(event, &policy.PathCache)
	} else if event.ChangeType == 2 {
		payload.ChangeType = "MODIFY"
	} else if event.ChangeType == 3 {
		payload.ChangeType = "DELETE"

	} else {
		payload.ChangeType = "COURRPTED"
	}

	payload.FilePath = constructPath(event, &policy.PathCache)

	return payload
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

	if ref == nil || ref.Parent == nil {
		return ""
	}

	parent_key := *ref.Parent
	parent_value, ok := p.Get(parent_key)
	if !ok {
		return ""
	}

	return pfs(&parent_value, p) + "/" + ref.Filename

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
func resolveUsername(uid uint32, gid uint32) string {

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

/*
ConvertMtimeToISO

@mtime  : mtime obtained from task struct in eBPF (seconds since epoch)
@return : "Unknown" if unable to convert

	"YYYY-MM-DD hh:MM:SS AM/PM" in IST
*/
func convertMtimeToISO(mtime int64) string {
	if mtime <= 0 {
		return "Unknown"
	}

	ist, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		return "Unknown"
	}

	t := time.Unix(mtime, 0).In(ist)

	// 12-hour format with AM/PM
	return t.Format("2006-01-02 03:04:05 PM")
}
