package collectors

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

func logicalPath(cctx *Context, rooted string) string {
	root := cctx.Options.Root
	if root == "" || root == "/" {
		if rooted == "" {
			return "/"
		}
		return filepath.Clean(rooted)
	}
	rel, err := filepath.Rel(root, rooted)
	if err != nil || rel == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(rel)
}

func fileOwnerIDs(info os.FileInfo) (uint64, uint64, bool) {
	sys := reflect.ValueOf(info.Sys())
	if !sys.IsValid() {
		return 0, 0, false
	}
	if sys.Kind() == reflect.Pointer {
		sys = sys.Elem()
	}
	if !sys.IsValid() {
		return 0, 0, false
	}
	uidField := sys.FieldByName("Uid")
	gidField := sys.FieldByName("Gid")
	if !uidField.IsValid() || !gidField.IsValid() {
		return 0, 0, false
	}
	uid, okUID := unsignedField(uidField)
	gid, okGID := unsignedField(gidField)
	return uid, gid, okUID && okGID
}

func unsignedField(field reflect.Value) (uint64, bool) {
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value := field.Int()
		if value < 0 {
			return 0, false
		}
		return uint64(value), true
	default:
		return 0, false
	}
}

func readableByCurrentUser(info os.FileInfo) bool {
	return accessByCurrentUser(info, 0o400, 0o040, 0o004)
}

func writableByCurrentUser(info os.FileInfo) bool {
	return accessByCurrentUser(info, 0o200, 0o020, 0o002)
}

func accessByCurrentUser(info os.FileInfo, ownerBit, groupBit, otherBit os.FileMode) bool {
	mode := info.Mode().Perm()
	if mode&otherBit != 0 {
		return true
	}
	uid, gid, ok := fileOwnerIDs(info)
	euid := os.Geteuid()
	if euid == 0 {
		return mode&(ownerBit|groupBit|otherBit) != 0
	}
	if ok && uint64(euid) == uid && mode&ownerBit != 0 {
		return true
	}
	egid := os.Getegid()
	if ok && uint64(egid) == gid && mode&groupBit != 0 {
		return true
	}
	groups, err := os.Getgroups()
	if err == nil && ok && mode&groupBit != 0 {
		for _, group := range groups {
			if uint64(group) == gid {
				return true
			}
		}
	}
	return false
}

func hasOption(options []string, needle string) bool {
	for _, option := range options {
		if option == needle {
			return true
		}
	}
	return false
}

func hasAnyOption(options []string, needles ...string) bool {
	for _, needle := range needles {
		if hasOption(options, needle) {
			return true
		}
	}
	return false
}

func cleanOptionalText(value string) string {
	return strings.TrimSpace(strings.TrimRight(value, "\x00"))
}
