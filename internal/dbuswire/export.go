package dbuswire

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Built-in interfaces of every exported object.
const (
	IntrospectableInterface = "org.freedesktop.DBus.Introspectable"
	PropertiesInterface     = "org.freedesktop.DBus.Properties"
	PeerInterface           = "org.freedesktop.DBus.Peer"
)

// MethodCall is an incoming call as a handler sees it.
type MethodCall struct {
	Sender string
	Path   ObjectPath
	Body   []any
}

// Method is an exported method. In and Out are the argument and reply
// signatures; a call whose arguments do not match In is refused before
// the handler runs.
type Method struct {
	Name     string
	In, Out  Signature
	InNames  []string
	OutNames []string
	// Handler returns the reply values (matching Out) or an error; an
	// *Error is sent as is, any other error as a generic
	// org.freedesktop.DBus.Error.Failed without its text.
	Handler func(call *MethodCall) ([]any, error)
}

// Property is a read-only exported property.
type Property struct {
	Name string
	Sig  Signature
	// Get returns the current value (matching Sig); it runs on the call
	// goroutine and must be safe to call concurrently with the program.
	Get func() any
}

// SignalDef declares a signal for introspection.
type SignalDef struct {
	Name  string
	Sig   Signature
	Names []string
}

// Interface is one exported interface.
type Interface struct {
	Name       string
	Methods    []Method
	Properties []Property
	Signals    []SignalDef
}

func (i *Interface) validate() error {
	if !ValidInterfaceName(i.Name) {
		return fmt.Errorf("%w: arayüz adı %q", ErrValue, i.Name)
	}
	for _, m := range i.Methods {
		if !ValidMemberName(m.Name) || !ValidSignature(m.In) || !ValidSignature(m.Out) || m.Handler == nil {
			return fmt.Errorf("%w: yöntem %q", ErrValue, m.Name)
		}
	}
	for _, p := range i.Properties {
		if !ValidMemberName(p.Name) || singleType(p.Sig) != nil || p.Get == nil {
			return fmt.Errorf("%w: özellik %q", ErrValue, p.Name)
		}
	}
	for _, s := range i.Signals {
		if !ValidMemberName(s.Name) || !ValidSignature(s.Sig) {
			return fmt.Errorf("%w: sinyal %q", ErrValue, s.Name)
		}
	}
	return nil
}

// Export publishes iface at path, replacing an earlier interface of the
// same name.
func (c *Conn) Export(path ObjectPath, iface *Interface) error {
	if !ValidObjectPath(string(path)) {
		return fmt.Errorf("%w: yol %q", ErrValue, path)
	}
	if err := iface.validate(); err != nil {
		return err
	}
	switch iface.Name {
	case IntrospectableInterface, PropertiesInterface, PeerInterface:
		return fmt.Errorf("%w: %s yerleşik", ErrValue, iface.Name)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.objects[path] == nil {
		c.objects[path] = map[string]*Interface{}
	}
	c.objects[path][iface.Name] = iface
	return nil
}

// Unexport removes an interface from path.
func (c *Conn) Unexport(path ObjectPath, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.objects[path], name)
	if len(c.objects[path]) == 0 {
		delete(c.objects, path)
	}
}

// EmitPropertiesChanged sends org.freedesktop.DBus.Properties.PropertiesChanged.
func (c *Conn) EmitPropertiesChanged(path ObjectPath, iface string, changed map[string]Variant, invalidated []string) error {
	if changed == nil {
		changed = map[string]Variant{}
	}
	if invalidated == nil {
		invalidated = []string{}
	}
	return c.Emit(path, PropertiesInterface, "PropertiesChanged", "sa{sv}as", iface, changed, invalidated)
}

func (c *Conn) lookup(path ObjectPath) (map[string]*Interface, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ifaces := map[string]*Interface{}
	for k, v := range c.objects[path] {
		ifaces[k] = v
	}
	// Child nodes for introspection.
	prefix := string(path)
	if prefix != "/" {
		prefix += "/"
	}
	seen := map[string]bool{}
	var children []string
	for p := range c.objects {
		s := string(p)
		if s == string(path) || !strings.HasPrefix(s, prefix) {
			continue
		}
		child, _, _ := strings.Cut(s[len(prefix):], "/")
		if child != "" && !seen[child] {
			seen[child] = true
			children = append(children, child)
		}
	}
	sort.Strings(children)
	return ifaces, children
}

func (c *Conn) handleCall(m *Message) {
	ifaces, children := c.lookup(m.Path)
	switch {
	case m.Interface == IntrospectableInterface || (m.Interface == "" && m.Member == "Introspect"):
		if m.Member != "Introspect" || m.Signature != "" {
			c.replyError(m, ErrNameUnknownMethod, "unknown method")
			return
		}
		_ = c.reply(m, "s", []any{introspectXML(ifaces, children)})
		return
	case m.Interface == PeerInterface:
		switch {
		case m.Member == "Ping" && m.Signature == "":
			_ = c.reply(m, "", nil)
		case m.Member == "GetMachineId" && m.Signature == "":
			if id := machineID(); id != "" {
				_ = c.reply(m, "s", []any{id})
			} else {
				c.replyError(m, ErrNameFailed, "no machine id")
			}
		default:
			c.replyError(m, ErrNameUnknownMethod, "unknown method")
		}
		return
	case m.Interface == PropertiesInterface:
		c.handleProperties(m, ifaces)
		return
	}
	if len(ifaces) == 0 {
		c.replyError(m, ErrNameUnknownObject, "unknown object")
		return
	}
	var method *Method
	if m.Interface != "" {
		iface, ok := ifaces[m.Interface]
		if !ok {
			c.replyError(m, ErrNameUnknownIface, "unknown interface")
			return
		}
		method = findMethod(iface, m.Member)
	} else {
		// No interface: the first method of that name, in name order.
		names := make([]string, 0, len(ifaces))
		for n := range ifaces {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if method = findMethod(ifaces[n], m.Member); method != nil {
				break
			}
		}
	}
	if method == nil {
		c.replyError(m, ErrNameUnknownMethod, "unknown method")
		return
	}
	if m.Signature != method.In {
		c.replyError(m, ErrNameInvalidArgs, "invalid arguments")
		return
	}
	out, err := runHandler(method.Handler, &MethodCall{Sender: m.Sender, Path: m.Path, Body: m.Body})
	if err != nil {
		var de *Error
		if errors.As(err, &de) && ValidInterfaceName(de.Name) {
			c.replyError(m, de.Name, de.Message)
		} else {
			c.replyError(m, ErrNameFailed, "operation failed")
		}
		return
	}
	if err := c.reply(m, method.Out, out); err != nil && !errors.Is(err, ErrClosed) {
		c.replyError(m, ErrNameFailed, "operation failed")
	}
}

func runHandler(h func(*MethodCall) ([]any, error), call *MethodCall) (out []any, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, errors.New("handler panicked")
		}
	}()
	return h(call)
}

func findMethod(iface *Interface, name string) *Method {
	for i := range iface.Methods {
		if iface.Methods[i].Name == name {
			return &iface.Methods[i]
		}
	}
	return nil
}

func findProperty(iface *Interface, name string) *Property {
	for i := range iface.Properties {
		if iface.Properties[i].Name == name {
			return &iface.Properties[i]
		}
	}
	return nil
}

func propertyValue(p *Property) (v Variant, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("property getter panicked")
		}
	}()
	return Variant{Sig: p.Sig, Value: p.Get()}, nil
}

func (c *Conn) handleProperties(m *Message, ifaces map[string]*Interface) {
	str := func(i int) string {
		if i < len(m.Body) {
			s, _ := m.Body[i].(string)
			return s
		}
		return ""
	}
	switch {
	case m.Member == "Get" && m.Signature == "ss":
		iface, ok := ifaces[str(0)]
		if !ok {
			c.replyError(m, ErrNameUnknownIface, "unknown interface")
			return
		}
		p := findProperty(iface, str(1))
		if p == nil {
			c.replyError(m, ErrNameUnknownProperty, "unknown property")
			return
		}
		v, err := propertyValue(p)
		if err != nil {
			c.replyError(m, ErrNameFailed, "operation failed")
			return
		}
		if err := c.reply(m, "v", []any{v}); err != nil && !errors.Is(err, ErrClosed) {
			c.replyError(m, ErrNameFailed, "operation failed")
		}
	case m.Member == "GetAll" && m.Signature == "s":
		all := map[string]Variant{}
		if iface, ok := ifaces[str(0)]; ok {
			for i := range iface.Properties {
				v, err := propertyValue(&iface.Properties[i])
				if err != nil {
					c.replyError(m, ErrNameFailed, "operation failed")
					return
				}
				all[iface.Properties[i].Name] = v
			}
		} else if len(ifaces) == 0 {
			c.replyError(m, ErrNameUnknownObject, "unknown object")
			return
		}
		if err := c.reply(m, "a{sv}", []any{all}); err != nil && !errors.Is(err, ErrClosed) {
			c.replyError(m, ErrNameFailed, "operation failed")
		}
	case m.Member == "Set" && m.Signature == "ssv":
		iface, ok := ifaces[str(0)]
		if !ok || findProperty(iface, str(1)) == nil {
			c.replyError(m, ErrNameUnknownProperty, "unknown property")
			return
		}
		c.replyError(m, ErrNameReadOnly, "read-only property")
	default:
		c.replyError(m, ErrNameUnknownMethod, "unknown method")
	}
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;")
	return r.Replace(s)
}

func argXML(b *strings.Builder, sig Signature, names []string, dir string) {
	parts, _ := SplitSignature(sig)
	for i, p := range parts {
		b.WriteString("      <arg")
		if i < len(names) && ValidMemberName(names[i]) {
			b.WriteString(` name="` + xmlEscape(names[i]) + `"`)
		}
		b.WriteString(` type="` + xmlEscape(p) + `"`)
		if dir != "" {
			b.WriteString(` direction="` + dir + `"`)
		}
		b.WriteString("/>\n")
	}
}

// introspectXML describes the interfaces at a path and its child nodes.
func introspectXML(ifaces map[string]*Interface, children []string) string {
	var b strings.Builder
	// No DOCTYPE: it names an outside address (ADR-0008) and readers do
	// not need it.
	b.WriteString("<node>\n")
	b.WriteString(`  <interface name="` + IntrospectableInterface + `">` + "\n" + `    <method name="Introspect">` + "\n" + `      <arg name="xml_data" type="s" direction="out"/>` + "\n    </method>\n  </interface>\n")
	b.WriteString(`  <interface name="` + PeerInterface + `">` + "\n" + `    <method name="Ping"/>` + "\n" + `    <method name="GetMachineId">` + "\n" + `      <arg name="machine_uuid" type="s" direction="out"/>` + "\n    </method>\n  </interface>\n")
	if len(ifaces) > 0 {
		b.WriteString(`  <interface name="` + PropertiesInterface + `">` + "\n")
		b.WriteString(`    <method name="Get"><arg name="interface_name" type="s" direction="in"/><arg name="property_name" type="s" direction="in"/><arg name="value" type="v" direction="out"/></method>` + "\n")
		b.WriteString(`    <method name="GetAll"><arg name="interface_name" type="s" direction="in"/><arg name="props" type="a{sv}" direction="out"/></method>` + "\n")
		b.WriteString(`    <method name="Set"><arg name="interface_name" type="s" direction="in"/><arg name="property_name" type="s" direction="in"/><arg name="value" type="v" direction="in"/></method>` + "\n")
		b.WriteString(`    <signal name="PropertiesChanged"><arg name="interface_name" type="s"/><arg name="changed_properties" type="a{sv}"/><arg name="invalidated_properties" type="as"/></signal>` + "\n")
		b.WriteString("  </interface>\n")
	}
	names := make([]string, 0, len(ifaces))
	for n := range ifaces {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		iface := ifaces[n]
		b.WriteString(`  <interface name="` + xmlEscape(iface.Name) + `">` + "\n")
		for _, m := range iface.Methods {
			b.WriteString(`    <method name="` + xmlEscape(m.Name) + `">` + "\n")
			argXML(&b, m.In, m.InNames, "in")
			argXML(&b, m.Out, m.OutNames, "out")
			b.WriteString("    </method>\n")
		}
		for _, s := range iface.Signals {
			b.WriteString(`    <signal name="` + xmlEscape(s.Name) + `">` + "\n")
			argXML(&b, s.Sig, s.Names, "")
			b.WriteString("    </signal>\n")
		}
		for _, p := range iface.Properties {
			b.WriteString(`    <property name="` + xmlEscape(p.Name) + `" type="` + xmlEscape(string(p.Sig)) + `" access="read"/>` + "\n")
		}
		b.WriteString("  </interface>\n")
	}
	for _, ch := range children {
		b.WriteString(`  <node name="` + xmlEscape(ch) + `"/>` + "\n")
	}
	b.WriteString("</node>\n")
	return b.String()
}

// machineID reads the D-Bus machine id (32 hex digits).
func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(p)
		if err != nil || len(data) > 64 {
			continue
		}
		id := strings.TrimSpace(string(data))
		if len(id) == 32 && strings.Trim(id, "0123456789abcdef") == "" {
			return id
		}
	}
	return ""
}
