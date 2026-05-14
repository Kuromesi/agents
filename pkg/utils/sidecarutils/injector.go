/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sidecarutils

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/mergepatch"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"

	"github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/utils/webhookutils"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

type Injector struct {
	mu      sync.RWMutex
	cache   cache.Cache
	configs map[string]*SidecarInjectConfig
	client  kubernetes.Interface
}

func NewRuntimeController(cfg *rest.Config, cache cache.Cache) (*Injector, error) {
	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	injector := &Injector{
		client:  kubeClient,
		cache:   cache,
		configs: map[string]*SidecarInjectConfig{},
	}

	if err := injector.initializeConfig(context.Background()); err != nil {
		return nil, err
	}

	return injector, nil
}

func (i *Injector) Start(ctx context.Context) error {
	informer, err := i.cache.GetInformer(ctx, &corev1.ConfigMap{})
	if err != nil {
		return err
	}

	namespace := webhookutils.GetNamespace()
	informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cm := obj.(*corev1.ConfigMap)
			if cm.Name == SandboxInjectionConfigName && namespace == cm.Namespace {
				i.onConfigChange(cm)
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			cm := cur.(*corev1.ConfigMap)
			if cm.Name == SandboxInjectionConfigName && namespace == cm.Namespace {
				i.onConfigChange(cm)
			}
		},
		DeleteFunc: func(obj interface{}) {
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok {
				return
			}
			if cm.Name == SandboxInjectionConfigName && namespace == cm.Namespace {
				i.onConfigDeleted()
			}
		},
	})

	return nil
}

func (i *Injector) onConfigChange(cm *corev1.ConfigMap) {
	klog.V(5).Info("injection config changed, reloading", "name", cm.Name)

	i.mu.Lock()
	defer i.mu.Unlock()

	for key, value := range cm.Data {
		if value == "" {
			continue
		}
		if i.configs[key] != nil && i.configs[key].raw == value {
			klog.V(5).Info("injection config key already exists and not updated, skipping", "key", key)
			continue
		}

		cfg, err := parseConfigValue(value)
		if err != nil {
			klog.ErrorS(err, "failed to parse injection config key", "key", key)
			continue
		}
		i.configs[key] = cfg
	}
}

func (i *Injector) InjectRuntime(ctx context.Context, sandbox *v1alpha1.Sandbox, pod *corev1.Pod) (*corev1.Pod, error) {
	for _, runtime := range sandbox.Spec.Runtimes {
		runTimeInjectConfig := i.FetchConfig(runtime.Name)
		if runTimeInjectConfig == nil {
			return nil, fmt.Errorf("injection config for runtime %s not found", runtime.Name)
		}

		switch runtime.Name {
		case v1alpha1.RuntimeConfigForInjectAgentRuntime:
			if !isContainersExists(pod.Spec.InitContainers, runTimeInjectConfig.Sidecars) &&
				!isContainersExists(pod.Spec.Containers, runTimeInjectConfig.Sidecars) {
				setAgentRuntimeContainer(ctx, &pod.Spec, runTimeInjectConfig)
			}
		case v1alpha1.RuntimeConfigForInjectCsiMount:
			if !isContainersExists(pod.Spec.InitContainers, runTimeInjectConfig.Sidecars) &&
				!isContainersExists(pod.Spec.Containers, runTimeInjectConfig.Sidecars) {
				setCSIMountContainer(ctx, &pod.Spec, runTimeInjectConfig)
			}
		default:
			var err error
			pod, err = applyTemplate(pod, runTimeInjectConfig.templatePod, runTimeInjectConfig.Template)
			if err != nil {
				return nil, fmt.Errorf("failed to apply overlay YAML for runtime %s: %v", runtime.Name, err)
			}
		}
	}

	if err := i.postProcessPod(sandbox, pod); err != nil {
		return nil, fmt.Errorf("failed to post process pod: %v", err)
	}
	return pod, nil
}

func (i *Injector) postProcessPod(sandbox *v1alpha1.Sandbox, pod *corev1.Pod) error {
	for _, runtime := range sandbox.Spec.Runtimes {
		if fn, ok := runtimePostProcessors[runtime.Name]; ok {
			if err := fn(pod); err != nil {
				return fmt.Errorf("post processor for runtime %s failed: %v", runtime.Name, err)
			}
		}
	}
	return nil
}

func (i *Injector) onConfigDeleted() {
	klog.V(5).Info("injection config deleted")

	i.mu.Lock()
	i.configs = map[string]*SidecarInjectConfig{}
	i.mu.Unlock()
}

// FetchConfig returns the pre-parsed SidecarInjectConfig for the given key.
// If the key doesn't exist or the ConfigMap hasn't been loaded, returns an empty config.
func (i *Injector) FetchConfig(key string) *SidecarInjectConfig {
	i.mu.RLock()
	defer i.mu.RUnlock()

	if cfg, ok := i.configs[key]; ok {
		return cfg
	}
	return nil
}

// parseConfigValue parses a single config value string (JSON or YAML) into SidecarInjectConfig.
func parseConfigValue(value string) (*SidecarInjectConfig, error) {
	sidecarConfig := &SidecarInjectConfig{}

	if err := yaml.Unmarshal([]byte(value), &sidecarConfig); err != nil {
		return nil, err
	}

	templatePod := &corev1.Pod{}
	if len(sidecarConfig.Template) > 0 {
		if err := json.Unmarshal(sidecarConfig.Template, templatePod); err != nil {
			return nil, err
		}
	}

	sidecarConfig.templatePod = templatePod
	sidecarConfig.raw = value
	return sidecarConfig, nil
}

// initializeConfig performs an initial synchronous load of the injection config.
// This is called during startup to ensure we have the current state before processing.
func (i *Injector) initializeConfig(ctx context.Context) error {
	cm, err := i.client.CoreV1().ConfigMaps(webhookutils.GetNamespace()).Get(ctx, SandboxInjectionConfigName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			klog.V(5).Info("injection configuration not found, skip loading")
			return nil
		}
		return err
	}

	i.onConfigChange(cm)
	return nil
}

func applyTemplate(target, templatePod *corev1.Pod, overlayYAML []byte) (*corev1.Pod, error) {
	if isContainersExists(target.Spec.InitContainers, templatePod.Spec.InitContainers) ||
		isContainersExists(target.Spec.Containers, templatePod.Spec.Containers) {
		return nil, fmt.Errorf("injection conflicts")
	}

	target, err := applyOverlayYAML(target, overlayYAML)
	if err != nil {
		return nil, err
	}

	return target, nil
}

func applyOverlayYAML(target *corev1.Pod, overlayYAML []byte) (*corev1.Pod, error) {
	currentJSON, err := json.Marshal(target)
	if err != nil {
		return nil, err
	}

	pod := corev1.Pod{}
	// Overlay the injected template onto the original podSpec
	patched, err := StrategicMergePatchYAML(currentJSON, overlayYAML, pod)
	if err != nil {
		return nil, fmt.Errorf("strategic merge: %v", err)
	}

	if err := json.Unmarshal(patched, &pod); err != nil {
		return nil, fmt.Errorf("unmarshal patched pod: %v", err)
	}
	return &pod, nil
}

// StrategicMergePatchYAML is a small fork of strategicpatch.StrategicMergePatch to allow YAML patches
// This avoids expensive conversion from YAML to JSON
func StrategicMergePatchYAML(originalJSON []byte, patchYAML []byte, dataStruct any) ([]byte, error) {
	schema, err := strategicpatch.NewPatchMetaFromStruct(dataStruct)
	if err != nil {
		return nil, err
	}

	originalMap, err := patchHandleUnmarshal(originalJSON, json.Unmarshal)
	if err != nil {
		return nil, err
	}
	patchMap, err := patchHandleUnmarshal(patchYAML, func(data []byte, v any) error {
		return yaml.Unmarshal(data, v)
	})
	if err != nil {
		return nil, err
	}

	result, err := strategicpatch.StrategicMergeMapPatchUsingLookupPatchMeta(originalMap, patchMap, schema)
	if err != nil {
		return nil, err
	}

	return json.Marshal(result)
}

func patchHandleUnmarshal(j []byte, unmarshal func(data []byte, v any) error) (map[string]any, error) {
	if j == nil {
		j = []byte("{}")
	}

	m := map[string]any{}
	err := unmarshal(j, &m)
	if err != nil {
		return nil, mergepatch.ErrBadJSONDoc
	}
	return m, nil
}
