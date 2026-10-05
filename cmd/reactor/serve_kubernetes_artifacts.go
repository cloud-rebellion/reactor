package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// kubernetesArtifactMountConfig requires a separately mounted artifact tree.
// A Job without this contract can register as a worker, claim a run, then
// repeatedly lose its lease because the pinned executable is absent.
func kubernetesArtifactMountConfig(privateRoot string) (pvc, artifactRoot string, err error) {
	pvc = os.Getenv("REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC")
	if !validKubernetesPVCName(pvc) {
		return "", "", errors.New("kubernetes autoscaler requires REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC as a valid PVC name")
	}
	artifactRoot = os.Getenv("REACTOR_WORKER_ARTIFACT_ROOT")
	if !validAbsoluteMountPath(artifactRoot) {
		return "", "", errors.New("kubernetes autoscaler requires REACTOR_WORKER_ARTIFACT_ROOT as a clean absolute mount path")
	}
	if !validAbsoluteMountPath(privateRoot) {
		return "", "", errors.New("kubernetes autoscaler requires --root as a clean absolute private state path")
	}
	// A shared PVC must never shadow the private worker state root that may
	// contain the vault key and writable operational state.
	rel, err := filepath.Rel(artifactRoot, privateRoot)
	if err != nil {
		return "", "", fmt.Errorf("kubernetes autoscaler: compare artifact and private roots: %w", err)
	}
	if rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", errors.New("REACTOR_WORKER_ARTIFACT_ROOT must not contain the private --root path")
	}
	return pvc, artifactRoot, nil
}

func validAbsoluteMountPath(path string) bool {
	if path == "" || path == string(filepath.Separator) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for _, char := range path {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func validKubernetesPVCName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			alnum := ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9'
			if !alnum && (i == 0 || i == len(label)-1 || ch != '-') {
				return false
			}
		}
	}
	return true
}
