package node

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/openscale/openscale/internal/securefile"
)

// Machine binding (F-137, ADR-0028): the device key is tied to the
// computer it was created on. The state directory keeps a digest of the
// operating system's machine id and the device id; when the directory is
// copied to another computer (disk image, cloned VM, copied backup) the
// tunnel refuses to start, because two computers with one identity would
// fight over it. The coordinator additionally reports identities seen at
// two places at once.
//
// The check is skipped where no stable machine id exists (containers,
// systems without one) and can be turned off with
// OPENSCALE_MACHINE_BINDING=off. After a deliberate move,
// RebindMachine (openscale device rebind) or
// OPENSCALE_ALLOW_MACHINE_CHANGE=1 accepts the new computer.

const (
	machineBindingFile   = "machine.json"
	machineBindingFormat = "openscale-machine-binding-v1"
)

// ErrMachineChanged is returned when the state directory was made on
// another computer.
var ErrMachineChanged = errors.New("bu cihazın kimliği başka bir bilgisayarda oluşturulmuş; kopyalanmış bir kimlik ağda çakışır. Bilerek taşıdıysanız 'openscale device rebind' çalıştırın, değilse bu bilgisayarı yeni bir davetle ekleyin")

type machineBinding struct {
	Format  string `json:"format"`
	Binding string `json:"binding"`
}

// CheckMachineBinding creates the binding on first use and compares it
// afterwards.
func CheckMachineBinding(stateDir, deviceID string) error {
	if stateDir == "" || machineBindingDisabled() {
		return nil
	}
	id, ok := machineID()
	if !ok {
		return nil
	}
	want := bindingDigest(id, deviceID)
	path := filepath.Join(stateDir, machineBindingFile)
	data, err := securefile.ReadPrivate(path, 1024)
	if errors.Is(err, fs.ErrNotExist) {
		return writeBinding(path, want)
	}
	if err != nil {
		return err
	}
	var b machineBinding
	if json.Unmarshal(data, &b) != nil || b.Format != machineBindingFormat {
		// A damaged file binds again rather than locking the device out.
		return writeBinding(path, want)
	}
	if subtle.ConstantTimeCompare([]byte(b.Binding), []byte(want)) == 1 {
		return nil
	}
	if os.Getenv("OPENSCALE_ALLOW_MACHINE_CHANGE") == "1" {
		return writeBinding(path, want)
	}
	return ErrMachineChanged
}

// RebindMachine accepts the current computer for the state directory.
func RebindMachine(stateDir, deviceID string) error {
	id, ok := machineID()
	if !ok {
		return errors.New("bu sistemde makine kimliği okunamıyor; bağlama kullanılmıyor")
	}
	return writeBinding(filepath.Join(stateDir, machineBindingFile), bindingDigest(id, deviceID))
}

func bindingDigest(machine, deviceID string) string {
	h := sha256.New()
	h.Write([]byte("openscale/machine-binding/v1\x00"))
	h.Write([]byte(deviceID))
	h.Write([]byte{0})
	h.Write([]byte(machine))
	return hex.EncodeToString(h.Sum(nil))
}

func writeBinding(path, digest string) error {
	data, err := json.Marshal(machineBinding{Format: machineBindingFormat, Binding: digest})
	if err != nil {
		return err
	}
	return securefile.Replace(path, data)
}

func machineBindingDisabled() bool {
	if strings.EqualFold(os.Getenv("OPENSCALE_MACHINE_BINDING"), "off") {
		return true
	}
	// Containers often share or regenerate the machine id with the image.
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" || os.Getenv("container") != "" {
		return true
	}
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}
