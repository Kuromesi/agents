package sidecarutils

import (
	egresscontrol "github.com/openkruise/agents/pkg/utils/sidecarutils/egress-control"
	corev1 "k8s.io/api/core/v1"
)

var runtimePostProcessors = map[string]PostProcessFunc{
	KEY_EGRESS_CONTROL_INJECTION_CONFIG: egresscontrol.ApplyHealthProbeRewrite,
}

// PostProcessFunc is a function that performs runtime-specific post-processing on a pod.
type PostProcessFunc func(pod *corev1.Pod) error
