package netlog

import (
	"testing"
)

func buildDummyPacket() Payload {
	var p Payload
	p.CheckSum = "dummy-checksum"
	p.FromIp = "127.0.0.1"

	p.FilePath = "/tmp/test.txt"
	p.Username = "root"
	p.Tty = "pts/0"
	p.ChangeType = "CREATE"
	p.TimeStamp = "2026-01-30T11:00:00Z"

	p.AfterSize = 22
	p.BeforeSize = 20
	p.FileSize = 22

	return p
}

var api APIAuth = APIAuth{
	AgentUUID: "dummy-uuid",
	APIKey:    "dummy-key",
	APIUrl:    "http://[IP_ADDRESS]/api",
}

func TestAPIReq(t *testing.T) {

	packet := buildDummyPacket()

	err := SendPOST(packet)

	if err != nil {
		t.Errorf("POST failed: %v \n Please start the fake-server first", err)
	}

	t.Log("POST successful")

}
