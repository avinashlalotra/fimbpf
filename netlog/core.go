package netlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

var AGENT_UUID string = "abc"
var API_KEY string = "xxxxx"

// Final Payload
type Payload struct {
	FromIp     string `json:"from_ip"`
	Tty        string `json:"tty"`
	FilePath   string `json:"file_path"`
	ChangeType string `json:"change_type"`
	Username   string `json:"username"`
	TimeStamp  string `json:"timestamp"`

	CheckSum string `json:"checksum"`

	FileSize   int64 `json:"file_size"`
	BeforeSize int64 `json:"before_size"`
	AfterSize  int64 `json:"after_size"`
}

func SendPOST(url string, payload Payload) error {

	data, err := json.Marshal(payload)

	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		url,
		bytes.NewBuffer(data))

	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-UUID", AGENT_UUID)
	req.Header.Set("X-API-Key", API_KEY)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 300 {
		return fmt.Errorf("POST failed (%d): %s", resp.StatusCode, body)
	}

	fmt.Println("Response:", string(body))

	return nil
}
