package wireguard

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"wireguard-core/internal/domain"
)

const disabledPeersSuffix = ".disabled_peers"

type DisabledPeerFileStore struct {
	configDir string
}

var _ domain.DisabledPeerStore = (*DisabledPeerFileStore)(nil)

func NewDisabledPeerFileStore(configDir string) *DisabledPeerFileStore {
	return &DisabledPeerFileStore{configDir: configDir}
}

func (s *DisabledPeerFileStore) filePath(deviceName string) string {
	return filepath.Join(s.configDir, deviceName+disabledPeersSuffix)
}

func (s *DisabledPeerFileStore) readKeys(deviceName string) (map[string]struct{}, error) {
	path := s.filePath(deviceName)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]struct{}), nil
		}
		return nil, err
	}
	keys := make(map[string]struct{})
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		key := strings.TrimSpace(sc.Text())
		if key != "" {
			keys[key] = struct{}{}
		}
	}
	return keys, sc.Err()
}

func (s *DisabledPeerFileStore) writeKeys(deviceName string, keys map[string]struct{}) error {
	path := s.filePath(deviceName)
	if len(keys) == 0 {
		_ = os.Remove(path)
		return nil
	}
	var b strings.Builder
	for k := range keys {
		b.WriteString(k)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0600)
}

func (s *DisabledPeerFileStore) Add(deviceName, publicKey string) error {
	keys, err := s.readKeys(deviceName)
	if err != nil {
		return err
	}
	keys[publicKey] = struct{}{}
	return s.writeKeys(deviceName, keys)
}

func (s *DisabledPeerFileStore) Remove(deviceName, publicKey string) error {
	keys, err := s.readKeys(deviceName)
	if err != nil {
		return err
	}
	delete(keys, publicKey)
	return s.writeKeys(deviceName, keys)
}

func (s *DisabledPeerFileStore) List(deviceName string) ([]string, error) {
	keys, err := s.readKeys(deviceName)
	if err != nil {
		return nil, err
	}
	list := make([]string, 0, len(keys))
	for k := range keys {
		list = append(list, k)
	}
	return list, nil
}

func (s *DisabledPeerFileStore) Contains(deviceName, publicKey string) (bool, error) {
	keys, err := s.readKeys(deviceName)
	if err != nil {
		return false, err
	}
	_, ok := keys[publicKey]
	return ok, nil
}
