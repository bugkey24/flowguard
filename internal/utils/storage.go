package utils

import (
	"encoding/json"
	"os"
	"sync"
)

type AliasMap map[string]string

var (
	dataFile = "devices.json"
	mutex    sync.Mutex
)

func LoadAliases() (AliasMap, error) {
	mutex.Lock()
	defer mutex.Unlock()

	if _, err := os.Stat(dataFile); os.IsNotExist(err) {
		return make(AliasMap), nil
	}

	data, err := os.ReadFile(dataFile)
	if err != nil {
		return nil, err
	}

	var aliases AliasMap
	if err := json.Unmarshal(data, &aliases); err != nil {
		return make(AliasMap), nil
	}
	return aliases, nil
}

func SaveAlias(mac string, name string) error {
	aliases, err := LoadAliases()
	if err != nil {
		return err
	}

	mutex.Lock()
	defer mutex.Unlock()

	aliases[mac] = name

	data, err := json.MarshalIndent(aliases, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(dataFile, data, 0644)
}