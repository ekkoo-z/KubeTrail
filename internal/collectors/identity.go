package collectors

import (
	"context"
	"os"
	"os/user"
	"strconv"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func collectIdentity(_ context.Context, _ *Context) ([]model.Fact, []model.ErrorEntry) {
	current, err := user.Current()
	var errs []model.ErrorEntry
	if err != nil {
		errs = append(errs, errEntry("os/user.Current", err))
	}

	groupIDs, err := os.Getgroups()
	if err != nil {
		errs = append(errs, errEntry("os.Getgroups", err))
	}

	groups := make([]map[string]string, 0, len(groupIDs))
	for _, gid := range groupIDs {
		item := map[string]string{"gid": strconv.Itoa(gid)}
		if group, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
			item["name"] = group.Name
		}
		groups = append(groups, item)
	}

	value := map[string]any{
		"uid":    os.Getuid(),
		"euid":   os.Geteuid(),
		"gid":    os.Getgid(),
		"egid":   os.Getegid(),
		"groups": groups,
	}
	if current != nil {
		value["username"] = current.Username
		value["name"] = current.Name
		value["homeDir"] = current.HomeDir
		value["userID"] = current.Uid
		value["groupID"] = current.Gid
	}

	return []model.Fact{
		fact("identity.current_user", "identity", "process", false, value),
	}, errs
}
