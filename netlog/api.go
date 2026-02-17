package netlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type APIAuth struct {
	AgentUUID string `json:"agent_uuid"`
	APIKey    string `json:"api_key"`
	APIUrl    string `json:"api_url"`
}

var Auth APIAuth

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

func InitApiAuth(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open API auth file: %w", err)
	}
	defer f.Close()

	// Decode JSON directly into the global struct
	if err := json.NewDecoder(f).Decode(&Auth); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate required fields
	if Auth.AgentUUID == "" {
		return fmt.Errorf("missing 'agent_uuid' in API auth file")
	}
	if Auth.APIKey == "" {
		return fmt.Errorf("missing 'api_key' in API auth file")
	}

	return nil
}

func SendPOST(payload Payload) error {

	data, err := json.Marshal(payload)

	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		Auth.APIUrl,
		bytes.NewBuffer(data))

	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-UUID", Auth.AgentUUID)
	req.Header.Set("X-API-Key", Auth.APIKey)

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
