package collectors

import (
	"context"
	"os"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func collectEnvironment(_ context.Context, _ *Context) ([]model.Fact, []model.ErrorEntry) {
	kubeVars := map[string]string{}
	secretLike := map[string]string{}
	allKeys := []string{}

	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		allKeys = append(allKeys, key)
		if strings.Contains(strings.ToUpper(key), "KUBE") {
			kubeVars[key] = value
		}
		if isSecretLike(key) {
			secretLike[key] = value
		}
	}

	return []model.Fact{
		fact("environment.kubernetes", "environment", "env", false, map[string]any{
			"inKubernetes":          os.Getenv("KUBERNETES_SERVICE_HOST") != "",
			"kubernetesServiceHost": os.Getenv("KUBERNETES_SERVICE_HOST"),
			"kubernetesVariables":   kubeVars,
		}),
		fact("environment.secret_like", "environment", "env", true, secretLike),
		fact("environment.keys", "environment", "env", false, allKeys),
	}, nil
}
