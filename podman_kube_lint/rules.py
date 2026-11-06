"""Podman 5.8 rule definitions and scanner constants."""

import re

DOC_VERSION = "5.8.0"
DOC_URL = "https://docs.podman.io/en/v5.8.0/markdown/podman-kube-play.1.html"

SEV_RANK = {"INFO": 1, "WARNING": 2, "ERROR": 3}
PH = "zzj2zz"  # Placeholder used for {{ ... }} in Jinja templates

# kind -> expected apiVersion (from the documentation's supported kinds)
SUPPORTED_KINDS = {
    "Pod": "v1",
    "Deployment": "apps/v1",
    "PersistentVolumeClaim": "v1",
    "ConfigMap": "v1",
    "Secret": "v1",
    "DaemonSet": "apps/v1",
    "Job": "batch/v1",
}

FILE_RE = re.compile(r"\.ya?ml(\.(j2|jinja2?|jinja))?$|\.(j2|jinja2?)$", re.I)
YAML_J2_RE = re.compile(r"\.ya?ml\.(j2|jinja2?|jinja)$", re.I)
J2_RE = re.compile(r"\.(j2|jinja2?|jinja)$", re.I)
DEFAULT_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"}

DNS_SUB = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
QTY = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+|[numkMGTPE]|[KMGTPE]i)?$")
KIND_GUESS = re.compile(r"(?m)^kind:\s*[\"']?([A-Za-z]+)")

# ---------------------------------------------------------------------------
# Field support tables from the documentation (True = supported, False = no, "na" = N/A)
# ---------------------------------------------------------------------------
_SELINUX = {"level": True, "role": True, "type": True, "user": True}
_WIN = False

CONTAINER = {
    "name": True, "image": True, "imagePullPolicy": True, "command": True, "args": True,
    "workingDir": True,
    "ports": {"containerPort": True, "hostIP": True, "hostPort": True, "name": True, "protocol": True},
    "env": {
        "name": True, "value": True,
        "valueFrom": {
            "configMapKeyRef": {"key": True, "name": True, "optional": True},
            "fieldRef": True, "resourceFieldRef": True,
            "secretKeyRef": {"key": True, "name": True, "optional": True},
        },
    },
    "envFrom": {
        "configMapRef": {"name": True, "optional": True},
        "prefix": False,
        "secretRef": {"name": True, "optional": True},
    },
    "volumeMounts": {
        "mountPath": True, "name": True, "mountPropagation": False, "readOnly": True,
        "subPath": True, "subPathExpr": False,
    },
    "volumeDevices": False,
    "resources": {"limits": True, "requests": True},
    "lifecycle": {"postStart": False, "preStop": False, "stopSignal": True},
    "terminationMessagePath": False, "terminationMessagePolicy": False,
    "livenessProbe": True, "readinessProbe": False, "startupProbe": False,
    "securityContext": {
        "runAsUser": True, "runAsNonRoot": False, "runAsGroup": True,
        "readOnlyRootFilesystem": True, "procMount": True, "privileged": True,
        "allowPrivilegeEscalation": True,
        "capabilities": {"add": True, "drop": True},
        "seccompProfile": False, "seLinuxOptions": _SELINUX, "windowsOptions": _WIN,
    },
    "stdin": False, "stdinOnce": False, "tty": False,
}

POD_SECURITY = {
    "runAsUser": True, "runAsNonRoot": False, "runAsGroup": True, "supplementalGroups": True,
    "fsGroup": False, "fsGroupChangePolicy": False, "seccompProfile": False,
    "seLinuxOptions": _SELINUX, "sysctls": {"name": True, "value": True}, "windowsOptions": _WIN,
}

POD_SPEC = {
    "containers": True, "initContainers": True, "volumes": True,
    "imagePullSecrets": False, "enableServiceLinks": False, "os": False,
    "nodeSelector": "na", "nodeName": "na", "affinity": "na", "tolerations": "na",
    "schedulerName": "na", "topologySpreadConstraints": "na",
    "runtimeClassName": False, "priorityClassName": False, "priority": False,
    "restartPolicy": True, "terminationGracePeriodSeconds": True,
    "activeDeadlineSeconds": False, "readinessGates": False,
    "hostname": True, "setHostnameAsFQDN": False, "subdomain": False,
    "hostAliases": {"hostnames": True, "ip": True},
    "dnsConfig": {"nameservers": True, "options": {"name": True, "value": True}, "searches": True},
    "dnsPolicy": False,
    "hostNetwork": True, "hostPID": True, "hostIPC": True, "shareProcessNamespace": True,
    "serviceAccountName": False, "automountServiceAccountToken": False,
    "securityContext": POD_SECURITY,
}

_BASE = {"apiVersion": True, "kind": True, "metadata": True, "status": True}
_TEMPLATE = {"metadata": True, "spec": True}
TOP = {
    "Pod": {**_BASE, "spec": True},
    "Deployment": {**_BASE, "spec": True},
    "DaemonSet": {**_BASE, "spec": True},
    "Job": {**_BASE, "spec": True},
    "PersistentVolumeClaim": {**_BASE, "spec": True},
    "ConfigMap": {**_BASE, "data": True, "binaryData": True, "immutable": False},
    "Secret": {**_BASE, "data": True, "stringData": True, "type": True, "immutable": True},
}
WORKLOAD_SPEC = {
    "Deployment": {
        "replicas": True, "selector": True, "template": _TEMPLATE,
        "minReadySeconds": False, "strategy": False, "revisionHistoryLimit": False,
        "progressDeadlineSeconds": False, "paused": False,
    },
    "DaemonSet": {
        "selector": True, "template": _TEMPLATE, "minReadySeconds": False,
        "strategy": False, "updateStrategy": False, "revisionHistoryLimit": False,
    },
    "Job": {
        "template": _TEMPLATE, "activeDeadlineSeconds": False, "selector": False,
        "backoffLimit": False, "completionMode": False, "completions": False,
        "manualSelector": False, "parallelism": False, "podFailurePolicy": False,
        "suspend": False, "ttlSecondsAfterFinished": False,
    },
}
PVC_SPEC = {
    "volumeName": False, "storageClassName": True, "volumeMode": False, "accessModes": True,
    "selector": False, "resources": {"limits": False, "requests": True},
}
META_KEYS = {
    "name", "namespace", "labels", "annotations", "generateName", "uid", "resourceVersion",
    "creationTimestamp", "generation", "ownerReferences", "finalizers", "managedFields", "selfLink",
}

PVC_ANNOTATIONS = {
    "volume.podman.io/driver", "volume.podman.io/device", "volume.podman.io/type",
    "volume.podman.io/uid", "volume.podman.io/gid", "volume.podman.io/mount-options",
    "volume.podman.io/import-source", "volume.podman.io/image",
}
KNOWN_POD_ANN = (
    "io.podman.annotations.userns", "io.podman.annotations.volumes-from/",
    "io.podman.annotations.infra.name", "io.podman.annotations.pids-limit/",
    "io.podman.annotations.cpuset/", "io.podman.annotations.memory-nodes/",
    "io.podman.annotations.kube.image.automount/", "io.podman.annotations.init.container.type",
)
HOSTPATH_TYPES = {"", "DirectoryOrCreate", "Directory", "FileOrCreate", "File", "Socket", "CharDevice", "BlockDevice"}
SUPPORTED_VOLUMES = ("hostPath", "emptyDir", "configMap", "persistentVolumeClaim", "image")
