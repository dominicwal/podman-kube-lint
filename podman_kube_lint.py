#!/usr/bin/env python3
"""Lint Podman kube play YAML manifests and Jinja YAML templates.

The supported fields and resource kinds are based on the Podman 5.8.0
documentation: https://docs.podman.io/en/v5.8.0/markdown/podman-kube-play.1.html
"""
from __future__ import annotations

import argparse
import base64
import binascii
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required. Install it with: python -m pip install PyYAML")

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


# ---------------------------------------------------------------------------
# YAML loader with line numbers and duplicate-key detection
# ---------------------------------------------------------------------------
class LDict(dict):
    def __init__(self):
        super().__init__()
        self.line = 0
        self.klines: dict = {}


class LList(list):
    def __init__(self):
        super().__init__()
        self.line = 0
        self.lines: list[int] = []


class Loader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self.dups: list[tuple] = []


def _construct_map(loader: Loader, node):
    loader.flatten_mapping(node)
    d = LDict()
    d.line = node.start_mark.line
    for kn, vn in node.value:
        k = loader.construct_object(kn, deep=True)
        try:
            hash(k)
        except TypeError:
            raise yaml.constructor.ConstructorError(None, None, "Key is not hashable", kn.start_mark)
        v = loader.construct_object(vn, deep=True)
        if k in d:
            loader.dups.append((k, kn.start_mark.line))
        d[k] = v
        d.klines[k] = kn.start_mark.line
    return d


def _construct_seq(loader: Loader, node):
    out = LList()
    out.line = node.start_mark.line
    for n in node.value:
        out.append(loader.construct_object(n, deep=True))
        out.lines.append(n.start_mark.line)
    return out


Loader.add_constructor("tag:yaml.org,2002:map", _construct_map)
Loader.add_constructor("tag:yaml.org,2002:seq", _construct_seq)


# ---------------------------------------------------------------------------
# Neutralize Jinja without rendering it; preserve line numbers
# ---------------------------------------------------------------------------
def neutralize_jinja(text: str) -> tuple[str, bool]:
    dynamic = False

    def blank(m):
        return "\n" * m.group(0).count("\n")

    text = re.sub(r"\{#.*?#\}", blank, text, flags=re.S)
    text = re.sub(r"\{%.*?%\}", blank, text, flags=re.S)

    def standalone(m):
        nonlocal dynamic
        dynamic = True
        return blank(m)

    # A line containing only {{ ... }} (for example, {{ x | to_nice_yaml | indent(4) }}) is a dynamic block.
    text = re.sub(r"(?m)^[ \t]*\{\{.*?\}\}[ \t]*$", standalone, text, flags=re.S)
    text = re.sub(r"\{\{.*?\}\}", lambda m: PH + "\n" * m.group(0).count("\n"), text, flags=re.S)
    return text, dynamic


def split_docs(text: str) -> list[tuple[int, str]]:
    """Teilt Multi-Doc-YAML an '---' – liefert (Startzeile 0-basiert, Text)."""
    docs, cur, start = [], [], 0
    for i, line in enumerate(text.split("\n")):
        if re.match(r"^---(\s|$)", line):
            docs.append((start, "\n".join(cur)))
            cur, start = [], i + 1
        elif re.match(r"^\.\.\.(\s|$)", line):
            continue
        else:
            cur.append(line)
    docs.append((start, "\n".join(cur)))
    return docs


def is_blank_doc(t: str) -> bool:
    return all(not l.strip() or l.strip().startswith("#") or l.startswith("%") for l in t.split("\n"))


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    file: str
    line: int
    severity: str
    rule: str
    message: str
    kind: str = ""
    name: str = ""
    snippet: str = ""


class Ctx:
    def __init__(self, file, offset, raw_lines, dynamic, is_j2, kind, index, out):
        self.file, self.offset, self.raw = file, offset, raw_lines
        self.dynamic, self.is_j2 = dynamic, is_j2
        self.kind, self.name = kind, ""
        self.index, self.out = index, out

    def add(self, sev, line, rule, msg):
        ln = (line or 0) + self.offset + 1
        snip = self.raw[ln - 1].strip() if 0 < ln <= len(self.raw) else ""
        self.out.append(Finding(self.file, ln, sev, rule, msg.replace(PH, "{{…}}"), self.kind,
                                self.name.replace(PH, "{{…}}"), snip[:160]))

    def err(self, line, rule, msg): self.add("ERROR", line, rule, msg)
    def warn(self, line, rule, msg): self.add("WARNING", line, rule, msg)
    def info(self, line, rule, msg): self.add("INFO", line, rule, msg)

    def req(self, line, rule, msg):
        """Report missing required fields as warnings in dynamic Jinja templates."""
        if self.dynamic:
            self.warn(line, rule, msg + "  (Jinja: may be generated by {{ }})")
        else:
            self.err(line, rule, msg)

    def ref(self, kind, name, line, optional):
        if optional is True or not isinstance(name, str) or PH in name:
            return
        if (kind, name) not in self.index:
            self.info(line, "PK-REF-NOT-IN-REPO",
                      f"{kind} '{name}' is referenced but is not defined in any YAML file in this repository "
                      f"(this is OK if supplied with --configmap, podman secret, or an existing volume)")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def kl(d, k):
    return d.klines.get(k, d.line) if isinstance(d, LDict) else 0


def is_ph(v):
    return isinstance(v, str) and PH in v


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def tn(v):
    if v is None: return "null"
    if isinstance(v, bool): return "Boolean"
    if isinstance(v, int): return "Zahl"
    if isinstance(v, float): return "float"
    if isinstance(v, str): return "string"
    if isinstance(v, list): return "list"
    if isinstance(v, dict): return "mapping"
    return type(v).__name__


TYPES = {
    "str": (lambda v: isinstance(v, str), "a string"),
    "int": (is_int, "an integer"),
    "bool": (lambda v: isinstance(v, bool), "ein Boolean"),
    "list": (lambda v: isinstance(v, list), "a list"),
    "map": (lambda v: isinstance(v, dict), "a mapping"),
}


def want(c: Ctx, obj, key, t, path, hint=""):
    """Validate a field's type when the field is present and not a placeholder."""
    if not isinstance(obj, LDict) or key not in obj:
        return True
    v = obj[key]
    if v is None or is_ph(v):
        return True
    ok, label = TYPES[t]
    if ok(v):
        return True
    c.err(kl(obj, key), "PK-TYPE", f"'{path}.{key}' must be {label}, got {tn(v)} ({v!r}){hint}")
    return False


def enum(c: Ctx, obj, key, allowed, path):
    if not isinstance(obj, LDict) or key not in obj:
        return
    v = obj[key]
    if v is None or is_ph(v):
        return
    if v not in allowed:
        c.err(kl(obj, key), "PK-ENUM", f"'{path}.{key}' = {v!r} is invalid; allowed values: {', '.join(sorted(allowed))}")


def str_list(c: Ctx, obj, key, path):
    v = obj.get(key) if isinstance(obj, LDict) else None
    if v is None or is_ph(v):
        return
    if not isinstance(v, LList):
        c.err(kl(obj, key), "PK-TYPE", f"'{path}.{key}' must be a list of strings, got {tn(v)}")
        return
    for i, x in enumerate(v):
        if not isinstance(x, str) and not is_ph(x):
            c.err(v.lines[i], "PK-TYPE",
                  f"'{path}.{key}[{i}]' must be a string, got {tn(x)} ({x!r}); quote the value")


def walk(c: Ctx, obj, spec, path):
    """Check every field against the documentation's support table."""
    if isinstance(obj, LList):
        for it in obj:
            if isinstance(it, LDict):
                walk(c, it, spec, path)
        return
    if not isinstance(obj, LDict):
        return
    for k, v in obj.items():
        line = kl(obj, k)
        p = f"{path}.{k}" if path else str(k)
        if k not in spec:
            c.warn(line, "PK-UNKNOWN-FIELD",
                   f"Field '{p}' is not listed in the Podman {DOC_VERSION} documentation (typo? It may be ignored or rejected.)")
            continue
        s = spec[k]
        if s is False:
            c.warn(line, "PK-UNSUPPORTED-FIELD", f"'{p}' is not supported by podman kube play {DOC_VERSION} (documentation: 'no')")
        elif s == "na":
            c.info(line, "PK-NA-FIELD", f"'{p}' does not apply to single-node Podman (documentation: N/A) and is ignored")
        elif isinstance(s, dict):
            walk(c, v, s, p)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def check_strmap(c, m, key, path):
    v = m.get(key) if isinstance(m, LDict) else None
    if v is None:
        return None
    if not isinstance(v, LDict):
        c.err(kl(m, key), "PK-TYPE", f"'{path}.{key}' must be a mapping, got {tn(v)}")
        return None
    for k, x in v.items():
        if not isinstance(x, str) and not is_ph(x):
            c.err(kl(v, k), "PK-TYPE",
                  f"'{path}.{key}.{k}' must be a string, got {tn(x)} ({x!r}); quote the value")
    return v


def check_metadata(c, md, parent_line, path, need_name, pvc=False):
    if not isinstance(md, LDict):
        if need_name:
            c.req(parent_line, "PK-META", f"'{path}' is missing or is not a mapping")
        return
    for k in md:
        if k not in META_KEYS:
            c.warn(kl(md, k), "PK-UNKNOWN-FIELD", f"Field '{path}.{k}' is not a recognized metadata field")
    if need_name:
        name = md.get("name")
        if not name:
            c.req(md.line, "PK-NAME-MISSING", f"'{path}.name' is missing")
        elif want(c, md, "name", "str", path) and isinstance(name, str):
            if len(name) > 253 or not DNS_SUB.match(name.lower() if PH in name else name):
                c.warn(kl(md, "name"), "PK-NAME-FORMAT",
                       f"Name {name!r} is not a valid Kubernetes name (DNS-1123: a-z 0-9 - .); Podman may accept values kubectl does not")
    if "namespace" in md:
        c.info(kl(md, "namespace"), "PK-NAMESPACE", "metadata.namespace is ignored by podman kube play")
    check_strmap(c, md, "labels", path)
    ann = check_strmap(c, md, "annotations", path)
    if ann:
        for k, v in ann.items():
            line = kl(ann, k)
            if k.startswith("io.podman.annotations.") and not k.startswith(KNOWN_POD_ANN):
                c.info(line, "PK-ANNOTATION", f"Annotation '{k}' is not listed in the kube play documentation (possibly from kube generate)")
            if k == "io.podman.annotations.init.container.type" and isinstance(v, str) and v not in ("once", "always"):
                c.err(line, "PK-ANNOTATION", f"'{k}' = {v!r} is invalid; allowed values: once, always")
            if pvc and k.startswith("volume.podman.io/") and k not in PVC_ANNOTATIONS:
                c.warn(line, "PK-ANNOTATION", f"Unknown PVC annotation '{k}'; documented annotations: {', '.join(sorted(PVC_ANNOTATIONS))}")
            if pvc and k in ("volume.podman.io/uid", "volume.podman.io/gid") and isinstance(v, str) \
                    and not is_ph(v) and not v.isdigit():
                c.err(line, "PK-ANNOTATION", f"'{k}' must be numeric, got {v!r}")


def check_quantity_map(c, ct, key, path):
    m = ct.get(key)
    if m is None:
        return
    if not isinstance(m, LDict):
        c.err(kl(ct, key), "PK-TYPE", f"'{path}.{key}' must be a mapping")
        return
    for k, v in m.items():
        if is_ph(v) or v is None:
            continue
        if isinstance(v, bool) or not isinstance(v, (int, float, str)) or not QTY.match(str(v)):
            c.err(kl(m, k), "PK-QUANTITY", f"'{path}.{key}.{k}' = {v!r} is not a valid Kubernetes quantity (for example, 500m, 128Mi, 1Gi)")


def check_probe(c, pr, line, path):
    if not isinstance(pr, LDict):
        c.err(line, "PK-TYPE", f"'{path}' must be a mapping")
        return
    handlers = [h for h in ("exec", "httpGet", "tcpSocket", "grpc") if h in pr]
    if not handlers:
        c.req(line, "PK-PROBE", f"'{path}' requires exactly one handler: exec, httpGet, tcpSocket, or grpc")
    elif len(handlers) > 1:
        c.err(line, "PK-PROBE", f"'{path}' has multiple handlers ({', '.join(handlers)}); only one is allowed")
    if isinstance(pr.get("exec"), LDict):
        str_list(c, pr["exec"], "command", f"{path}.exec")
    for k in ("initialDelaySeconds", "timeoutSeconds", "periodSeconds", "successThreshold", "failureThreshold"):
        want(c, pr, k, "int", path)


def check_ports(c, ports, line, path):
    if not isinstance(ports, LList):
        c.err(line, "PK-TYPE", f"'{path}.ports' must be a list")
        return
    seen = set()
    for i, p in enumerate(ports):
        pl, pp = ports.lines[i], f"{path}.ports[{i}]"
        if not isinstance(p, LDict):
            c.err(pl, "PK-TYPE", f"'{pp}' must be a mapping")
            continue
        if "containerPort" not in p:
            c.req(pl, "PK-PORT", f"'{pp}.containerPort' is missing")
        for k in ("containerPort", "hostPort"):
            if want(c, p, k, "int", pp) and k in p and is_int(p[k]):
                lo = 1 if k == "containerPort" else 0
                if not lo <= p[k] <= 65535:
                    c.err(kl(p, k), "PK-PORT", f"'{pp}.{k}' = {p[k]} is outside {lo}-65535")
        want(c, p, "name", "str", pp)
        want(c, p, "hostIP", "str", pp)
        enum(c, p, "protocol", {"TCP", "UDP", "SCTP"}, pp)
        key = (p.get("containerPort"), p.get("protocol", "TCP"))
        if is_int(key[0]):
            if key in seen:
                c.err(pl, "PK-PORT", f"'{pp}': containerPort {key[0]}/{key[1]} is duplicated")
            seen.add(key)


def check_env(c, env, line, path):
    if not isinstance(env, LList):
        c.err(line, "PK-TYPE", f"'{path}.env' must be a list")
        return
    for i, e in enumerate(env):
        el, ep = env.lines[i], f"{path}.env[{i}]"
        if not isinstance(e, LDict):
            c.err(el, "PK-TYPE", f"'{ep}' must be a mapping")
            continue
        if not e.get("name"):
            c.req(el, "PK-ENV", f"'{ep}.name' is missing")
        want(c, e, "name", "str", ep)
        want(c, e, "value", "str", ep,
             hint=" (Kubernetes/Podman expect a string; YAML converts true/8080/1.0 to non-strings. Quote the value.)")
        vf = e.get("valueFrom")
        if vf is not None:
            if "value" in e:
                c.err(el, "PK-ENV", f"'{ep}' has both value and valueFrom; only one is allowed")
            if not isinstance(vf, LDict):
                c.err(kl(e, "valueFrom"), "PK-TYPE", f"'{ep}.valueFrom' must be a mapping")
                continue
            srcs = [k for k in ("configMapKeyRef", "secretKeyRef", "fieldRef", "resourceFieldRef") if k in vf]
            if len(srcs) != 1 and not c.dynamic:
                c.err(kl(e, "valueFrom"), "PK-ENV", f"'{ep}.valueFrom' requires exactly one source (configMapKeyRef, secretKeyRef, fieldRef, or resourceFieldRef)")
            for s, kind in (("configMapKeyRef", "ConfigMap"), ("secretKeyRef", "Secret")):
                r = vf.get(s)
                if isinstance(r, LDict):
                    for need in ("name", "key"):
                        if not r.get(need):
                            c.req(kl(vf, s), "PK-ENV", f"'{ep}.valueFrom.{s}.{need}' is missing")
                    want(c, r, "optional", "bool", f"{ep}.valueFrom.{s}")
                    c.ref(kind, r.get("name"), kl(vf, s), r.get("optional"))
        elif "value" not in e and not c.dynamic:
            c.info(el, "PK-ENV-EMPTY", f"'{ep}' has neither value nor valueFrom (empty value)")


def check_envfrom(c, ef, line, path):
    if not isinstance(ef, LList):
        c.err(line, "PK-TYPE", f"'{path}.envFrom' must be a list")
        return
    for i, e in enumerate(ef):
        el, ep = ef.lines[i], f"{path}.envFrom[{i}]"
        if not isinstance(e, LDict):
            c.err(el, "PK-TYPE", f"'{ep}' must be a mapping")
            continue
        srcs = [k for k in ("configMapRef", "secretRef") if k in e]
        if len(srcs) != 1 and not c.dynamic:
            c.err(el, "PK-ENVFROM", f"'{ep}' requires exactly one of configMapRef or secretRef")
        for s, kind in (("configMapRef", "ConfigMap"), ("secretRef", "Secret")):
            r = e.get(s)
            if isinstance(r, LDict):
                if not r.get("name"):
                    c.req(kl(e, s), "PK-ENVFROM", f"'{ep}.{s}.name' is missing")
                want(c, r, "optional", "bool", f"{ep}.{s}")
                c.ref(kind, r.get("name"), kl(e, s), r.get("optional"))


def check_container(c, ct, line, path, volnames, seen):
    if not isinstance(ct, LDict):
        c.err(line, "PK-TYPE", f"'{path}' must be a mapping")
        return
    walk(c, ct, CONTAINER, path)

    name = ct.get("name")
    if not name:
        c.req(line, "PK-CONTAINER-NAME", f"'{path}.name' is missing")
    elif want(c, ct, "name", "str", path) and isinstance(name, str):
        if name in seen:
            c.err(kl(ct, "name"), "PK-DUPLICATE", f"Container name {name!r} is duplicated in the pod")
        seen.add(name)
        if not DNS_LABEL.match(name):
            c.warn(kl(ct, "name"), "PK-NAME-FORMAT", f"Container name {name!r} is not a DNS-1123 label (a-z 0-9 -)")

    img = ct.get("image")
    if not img:
        c.req(line, "PK-IMAGE-MISSING", f"'{path}.image' is missing")
    elif want(c, ct, "image", "str", path) and isinstance(img, str) and re.search(r"\s", img):
        c.err(kl(ct, "image"), "PK-IMAGE", f"'{path}.image' = {img!r} contains whitespace")

    enum(c, ct, "imagePullPolicy", {"Always", "Never", "IfNotPresent"}, path)
    want(c, ct, "workingDir", "str", path)
    str_list(c, ct, "command", path)
    str_list(c, ct, "args", path)

    if "ports" in ct and ct["ports"] is not None:
        check_ports(c, ct["ports"], kl(ct, "ports"), path)
    if ct.get("env") is not None:
        check_env(c, ct["env"], kl(ct, "env"), path)
    if ct.get("envFrom") is not None:
        check_envfrom(c, ct["envFrom"], kl(ct, "envFrom"), path)

    res = ct.get("resources")
    if isinstance(res, LDict):
        check_quantity_map(c, res, "limits", f"{path}.resources")
        check_quantity_map(c, res, "requests", f"{path}.resources")

    vm = ct.get("volumeMounts")
    if vm is not None:
        if not isinstance(vm, LList):
            c.err(kl(ct, "volumeMounts"), "PK-TYPE", f"'{path}.volumeMounts' must be a list")
        else:
            for i, m in enumerate(vm):
                ml, mp = vm.lines[i], f"{path}.volumeMounts[{i}]"
                if not isinstance(m, LDict):
                    c.err(ml, "PK-TYPE", f"'{mp}' must be a mapping")
                    continue
                if not m.get("mountPath"):
                    c.req(ml, "PK-MOUNT", f"'{mp}.mountPath' is missing")
                if not m.get("name"):
                    c.req(ml, "PK-MOUNT", f"'{mp}.name' is missing")
                elif isinstance(m["name"], str) and not is_ph(m["name"]) and m["name"] not in volnames:
                    c.req(kl(m, "name"), "PK-MOUNT-NO-VOLUME",
                          f"'{mp}' references volume {m['name']!r}, which is not defined in spec.volumes")
                want(c, m, "mountPath", "str", mp)
                want(c, m, "readOnly", "bool", mp)
                want(c, m, "subPath", "str", mp)

    if "livenessProbe" in ct and ct["livenessProbe"] is not None:
        check_probe(c, ct["livenessProbe"], kl(ct, "livenessProbe"), f"{path}.livenessProbe")

    sc = ct.get("securityContext")
    if isinstance(sc, LDict):
        sp = f"{path}.securityContext"
        for k in ("privileged", "readOnlyRootFilesystem", "allowPrivilegeEscalation"):
            want(c, sc, k, "bool", sp)
        for k in ("runAsUser", "runAsGroup"):
            want(c, sc, k, "int", sp)
        caps = sc.get("capabilities")
        if isinstance(caps, LDict):
            str_list(c, caps, "add", f"{sp}.capabilities")
            str_list(c, caps, "drop", f"{sp}.capabilities")


def check_volumes(c, spec, path):
    vols = spec.get("volumes")
    names = set()
    if vols is None:
        return names
    if not isinstance(vols, LList):
        c.err(kl(spec, "volumes"), "PK-TYPE", f"'{path}.volumes' must be a list")
        return names
    for i, v in enumerate(vols):
        vl, vp = vols.lines[i], f"{path}.volumes[{i}]"
        if not isinstance(v, LDict):
            c.err(vl, "PK-TYPE", f"'{vp}' must be a mapping")
            continue
        n = v.get("name")
        if not n:
            c.req(vl, "PK-VOLUME", f"'{vp}.name' is missing")
        elif isinstance(n, str):
            if n in names:
                c.err(kl(v, "name"), "PK-DUPLICATE", f"Volume name {n!r} is duplicated")
            names.add(n)
        srcs = [k for k in v if k != "name"]
        if not srcs:
            c.req(vl, "PK-VOLUME", f"'{vp}' has no volume source ({', '.join(SUPPORTED_VOLUMES)})")
            continue
        if len(srcs) > 1:
            c.err(vl, "PK-VOLUME", f"'{vp}' has multiple sources ({', '.join(srcs)}); only one is allowed")
        for s in srcs:
            sl, sv = kl(v, s), v[s]
            if s == "secret":
                c.warn(sl, "PK-VOLUME-TYPE",
                       f"'{vp}.secret': volume type is not listed in the {DOC_VERSION} documentation (listed types: {', '.join(SUPPORTED_VOLUMES)})")
            elif s not in SUPPORTED_VOLUMES:
                c.err(sl, "PK-VOLUME-TYPE",
                      f"'{vp}.{s}': volume type is not supported by kube play (supported types: {', '.join(SUPPORTED_VOLUMES)})")
            elif s == "hostPath":
                if not isinstance(sv, LDict) or not sv.get("path"):
                    c.req(sl, "PK-VOLUME", f"'{vp}.hostPath.path' is missing")
                else:
                    want(c, sv, "path", "str", f"{vp}.hostPath")
                    t = sv.get("type")
                    if t is not None and not is_ph(t) and t not in HOSTPATH_TYPES:
                        c.err(kl(sv, "type"), "PK-VOLUME",
                              f"'{vp}.hostPath.type' = {t!r} is not supported; allowed values: (empty), {', '.join(sorted(HOSTPATH_TYPES - {''}))}")
            elif s == "persistentVolumeClaim":
                if not isinstance(sv, LDict) or not sv.get("claimName"):
                    c.req(sl, "PK-VOLUME", f"'{vp}.persistentVolumeClaim.claimName' is missing")
                else:
                    c.ref("PersistentVolumeClaim", sv["claimName"], sl, None)
            elif s == "configMap":
                if not isinstance(sv, LDict) or not sv.get("name"):
                    c.req(sl, "PK-VOLUME", f"'{vp}.configMap.name' is missing")
                else:
                    c.ref("ConfigMap", sv["name"], sl, sv.get("optional"))
            elif s == "image":
                if not isinstance(sv, LDict) or not sv.get("reference"):
                    c.req(sl, "PK-VOLUME", f"'{vp}.image.reference' is missing")
                c.info(sl, "PK-IMAGE-VOLUME", "Image volume: image must be available locally; rootful mode only (documentation)")
    return names


def check_pod_spec(c, spec, line, path):
    if not isinstance(spec, LDict):
        c.req(line, "PK-SPEC", f"'{path}' is missing or is not a mapping")
        return
    walk(c, spec, POD_SPEC, path)
    volnames = check_volumes(c, spec, path)

    cs = spec.get("containers")
    if not isinstance(cs, LList) or not cs:
        c.req(kl(spec, "containers") if "containers" in spec else spec.line,
              "PK-NO-CONTAINERS", f"'{path}.containers' is missing or empty")
    seen: set = set()
    for group in ("containers", "initContainers"):
        items = spec.get(group)
        if items is None:
            continue
        if not isinstance(items, LList):
            c.err(kl(spec, group), "PK-TYPE", f"'{path}.{group}' must be a list, got {tn(items)}")
            continue
        for i, ct in enumerate(items):
            check_container(c, ct, items.lines[i], f"{path}.{group}[{i}]", volnames, seen)

    enum(c, spec, "restartPolicy", {"Always", "OnFailure", "Never"}, path)
    for k in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"):
        want(c, spec, k, "bool", path)
    want(c, spec, "terminationGracePeriodSeconds", "int", path)
    want(c, spec, "hostname", "str", path)
    sc = spec.get("securityContext")
    if isinstance(sc, LDict):
        for k in ("runAsUser", "runAsGroup"):
            want(c, sc, k, "int", f"{path}.securityContext")
        sg = sc.get("supplementalGroups")
        if isinstance(sg, LList):
            for i, g in enumerate(sg):
                if not is_int(g) and not is_ph(g):
                    c.err(sg.lines[i], "PK-TYPE", f"'{path}.securityContext.supplementalGroups[{i}]' must be a number")


def check_template(c, spec, path, kind):
    tpl = spec.get("template")
    if not isinstance(tpl, LDict):
        c.req(spec.line, "PK-TEMPLATE", f"'{path}.template' is missing")
        return None
    check_metadata(c, tpl.get("metadata"), tpl.line, f"{path}.template.metadata", need_name=False)
    check_pod_spec(c, tpl.get("spec"), tpl.line, f"{path}.template.spec")
    return tpl


def check_doc(c: Ctx, d: LDict, kind: str):
    walk(c, d, TOP[kind], "")
    api = d.get("apiVersion")
    if not api:
        c.err(d.line, "PK-APIVERSION", "apiVersion is missing")
    elif isinstance(api, str) and not is_ph(api) and api != SUPPORTED_KINDS[kind]:
        c.err(kl(d, "apiVersion"), "PK-APIVERSION",
              f"apiVersion {api!r} does not match kind {kind} (expected: {SUPPORTED_KINDS[kind]})")
    elif not isinstance(api, str):
        c.err(kl(d, "apiVersion"), "PK-TYPE", "apiVersion must be a string")

    check_metadata(c, d.get("metadata"), d.line, "metadata", need_name=True, pvc=(kind == "PersistentVolumeClaim"))
    spec = d.get("spec")

    if kind == "Pod":
        check_pod_spec(c, spec, d.line, "spec")

    elif kind in WORKLOAD_SPEC:
        if not isinstance(spec, LDict):
            c.req(d.line, "PK-SPEC", "'spec' is missing or is not a mapping")
            return
        walk(c, spec, WORKLOAD_SPEC[kind], "spec")
        tpl = check_template(c, spec, "spec", kind)
        if kind == "Deployment":
            want(c, spec, "replicas", "int", "spec")
            if is_int(spec.get("replicas")) and spec["replicas"] != 1:
                c.info(kl(spec, "replicas"), "PK-REPLICAS",
                       f"replicas: {spec['replicas']} – Podman ignores this value and starts 1 replica (documentation)")
        if kind in ("Deployment", "DaemonSet"):
            sel = spec.get("selector")
            ml = sel.get("matchLabels") if isinstance(sel, LDict) else None
            if not isinstance(ml, LDict):
                c.warn(kl(spec, "selector") if "selector" in spec else spec.line, "PK-SELECTOR",
                       "spec.selector.matchLabels is missing (required by Kubernetes)")
            elif tpl is not None and isinstance(tpl.get("metadata"), LDict):
                labels = tpl["metadata"].get("labels")
                if not isinstance(labels, LDict):
                    c.warn(tpl.line, "PK-SELECTOR", "spec.template.metadata.labels is missing; selector.matchLabels cannot match")
                else:
                    bad = [k for k, v in ml.items() if labels.get(k) != v and not is_ph(v) and not is_ph(labels.get(k))]
                    if bad:
                        c.warn(kl(sel, "matchLabels"), "PK-SELECTOR",
                               f"selector.matchLabels ({', '.join(bad)}) does not match template.metadata.labels")
        if kind == "Job" and tpl is not None and isinstance(tpl.get("spec"), LDict):
            rp = tpl["spec"].get("restartPolicy")
            if rp not in ("OnFailure", "Never") and not is_ph(rp):
                c.warn(kl(tpl, "spec"), "PK-JOB-RESTART",
                       "A Job requires spec.template.spec.restartPolicy to be OnFailure or Never (Kubernetes); Podman's default is 'always'")

    elif kind == "PersistentVolumeClaim":
        if not isinstance(spec, LDict):
            c.req(d.line, "PK-SPEC", "'spec' is missing or is not a mapping")
            return
        walk(c, spec, PVC_SPEC, "spec")
        am = spec.get("accessModes")
        if isinstance(am, LList):
            for i, m in enumerate(am):
                if m not in ("ReadWriteOnce", "ReadOnlyMany", "ReadWriteMany", "ReadWriteOncePod") and not is_ph(m):
                    c.err(am.lines[i], "PK-ENUM", f"accessModes[{i}] = {m!r} is invalid")
        elif am is not None and not is_ph(am):
            c.err(kl(spec, "accessModes"), "PK-TYPE", "spec.accessModes must be a list")
        req = spec.get("resources")
        storage = req.get("requests", {}).get("storage") if isinstance(req, LDict) and isinstance(req.get("requests"), LDict) else None
        if storage is None:
            c.warn(spec.line, "PK-PVC-STORAGE", "spec.resources.requests.storage is missing (Podman only needs the name; Kubernetes requires it)")
        check_quantity_map(c, req, "requests", "spec.resources") if isinstance(req, LDict) else None

    elif kind == "ConfigMap":
        for key in ("data", "binaryData"):
            m = d.get(key)
            if m is None:
                continue
            if not isinstance(m, LDict):
                c.err(kl(d, key), "PK-TYPE", f"'{key}' must be a mapping")
                continue
            for k, v in m.items():
                if not re.match(r"^[-._a-zA-Z0-9]+$", str(k)) and PH not in str(k):
                    c.err(kl(m, k), "PK-KEY", f"{key} key {k!r} is invalid (allowed: a-z A-Z 0-9 - _ .)")
                if key == "data" and not isinstance(v, str) and not is_ph(v):
                    c.err(kl(m, k), "PK-TYPE",
                          f"data.{k} must be a string, got {tn(v)} ({v!r}); quote the value")
                if key == "binaryData":
                    check_b64(c, m, k, f"binaryData.{k}")
        if d.get("data") is None and d.get("binaryData") is None and not c.dynamic:
            c.info(d.line, "PK-CM-EMPTY", "ConfigMap has no data or binaryData")

    elif kind == "Secret":
        for key in ("data", "stringData"):
            m = d.get(key)
            if m is None:
                continue
            if not isinstance(m, LDict):
                c.err(kl(d, key), "PK-TYPE", f"'{key}' must be a mapping")
                continue
            for k, v in m.items():
                if key == "data":
                    check_b64(c, m, k, f"data.{k}")
                elif not isinstance(v, str) and not is_ph(v):
                    c.err(kl(m, k), "PK-TYPE", f"stringData.{k} must be a string, got {tn(v)}")
        if d.get("data") is None and d.get("stringData") is None and not c.dynamic:
            c.info(d.line, "PK-SECRET-EMPTY", "Secret has no data or stringData")


def check_b64(c, m, k, path):
    v = m[k]
    if is_ph(v):
        return
    if not isinstance(v, str):
        c.err(kl(m, k), "PK-TYPE", f"'{path}' must be a base64 string, got {tn(v)}")
        return
    try:
        base64.b64decode(re.sub(r"\s+", "", v), validate=True)
    except (binascii.Error, ValueError):
        c.err(kl(m, k), "PK-BASE64", f"'{path}' is not valid base64 (use stringData for plain text)")


# ---------------------------------------------------------------------------
# File pipeline
# ---------------------------------------------------------------------------
@dataclass
class Chunk:
    offset: int
    data: object = None
    error: Exception | None = None
    guess: str = ""
    dups: list | None = None


@dataclass
class ParsedFile:
    rel: str
    raw: list
    is_j2: bool
    dynamic: bool
    chunks: list
    podman: bool


def parse_file(path: Path, rel: str, all_kinds: bool) -> ParsedFile | None:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    except OSError:
        return None
    raw = text.split("\n")
    is_j2 = bool(J2_RE.search(path.name))
    dynamic = False
    if is_j2:
        text, dynamic = neutralize_jinja(text)
    chunks = []
    for off, t in split_docs(text):
        if is_blank_doc(t):
            continue
        ch = Chunk(offset=off, guess=(KIND_GUESS.search(t).group(1) if KIND_GUESS.search(t) else ""))
        ld = Loader(t)
        try:
            ch.data = ld.get_single_data()
            ch.dups = ld.dups
        except yaml.YAMLError as e:
            ch.error = e
        finally:
            ld.dispose()
        chunks.append(ch)
    podman = False
    for ch in chunks:
        if isinstance(ch.data, dict):
            k = ch.data.get("kind")
            if k in SUPPORTED_KINDS or (all_kinds and k and ch.data.get("apiVersion")):
                podman = True
        elif ch.error and ch.guess in SUPPORTED_KINDS:
            podman = True
    if not podman:
        return None
    return ParsedFile(rel, raw, is_j2, dynamic, chunks, podman)


def analyze(pf: ParsedFile, index: set, out: list, all_kinds: bool):
    seen_docs: dict = {}
    for ch in pf.chunks:
        c = Ctx(pf.rel, ch.offset, pf.raw, pf.dynamic, pf.is_j2, ch.guess, index, out)
        if ch.error is not None:
            mark = getattr(ch.error, "problem_mark", None)
            prob = getattr(ch.error, "problem", None) or str(ch.error)
            ctx = getattr(ch.error, "context", None)
            c.err(mark.line if mark else 0, "PK-SYNTAX", f"YAML syntax error: {prob}" + (f" ({ctx})" if ctx else ""))
            continue
        d = ch.data
        if not isinstance(d, LDict):
            c.err(0, "PK-NO-MAPPING", f"Document is not a mapping; got {tn(d)} (check indentation)")
            continue
        kind = d.get("kind")
        c.kind = kind if isinstance(kind, str) else ""
        md = d.get("metadata")
        if isinstance(md, LDict) and isinstance(md.get("name"), str):
            c.name = md["name"]
        for k, line in (ch.dups or []):
            (c.warn if pf.is_j2 else c.err)(line, "PK-DUP-KEY",
                                             f"Duplicate key {k!r}" + (" (may be from an if/else branch in a Jinja template)" if pf.is_j2 else ""))
        if kind is None:
            c.err(d.line, "PK-NO-KIND", "Document has no 'kind'; podman kube play will reject it")
            continue
        if not isinstance(kind, str) or kind not in SUPPORTED_KINDS:
            c.warn(kl(d, "kind"), "PK-KIND-UNSUPPORTED",
                   f"kind {kind!r} is not supported by podman kube play {DOC_VERSION} "
                   f"(supported kinds: {', '.join(SUPPORTED_KINDS)}) – this file would not start")
            continue
        key = (kind, c.name)
        if c.name and key in seen_docs:
            c.err(d.line, "PK-DUPLICATE", f"{kind} {c.name!r} is defined more than once in this file (first definition: line {seen_docs[key]})")
        else:
            seen_docs[key] = d.line + ch.offset + 1
        check_doc(c, d, kind)


def iter_files(roots, excludes, skip_dirs):
    for root in roots:
        root = Path(root)
        if root.is_file():
            yield root, root.parent
            continue
        for dp, dns, fns in os.walk(root, followlinks=False):
            dns[:] = sorted(d for d in dns if d not in skip_dirs)
            for fn in sorted(fns):
                if not FILE_RE.search(fn):
                    continue
                p = Path(dp) / fn
                rel = p.relative_to(root).as_posix()
                if any(fnmatch.fnmatch(rel, ex) or fnmatch.fnmatch(fn, ex) or ex in rel.split("/") for ex in excludes):
                    continue
                if J2_RE.search(fn) and not YAML_J2_RE.search(fn) and not re.search(r"\.ya?ml", fn, re.I):
                    continue  # For example, nginx.conf.j2
                yield p, root


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
class Col:
    def __init__(self, on):
        self.on = on

    def __call__(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.on else s


def render_text(findings, stats, col, min_sev, snippet):
    lines = []
    sev_col = {"ERROR": "31;1", "WARNING": "33;1", "INFO": "36"}
    shown = [f for f in findings if SEV_RANK[f.severity] >= SEV_RANK[min_sev]]
    cur = None
    for f in sorted(shown, key=lambda f: (f.file, f.line, -SEV_RANK[f.severity])):
        if f.file != cur:
            cur = f.file
            lines += ["", col("1", cur)]
        who = f" [{f.kind}/{f.name}]" if f.kind and f.name else (f" [{f.kind}]" if f.kind else "")
        lines.append(f"  {col('2', f'L{f.line:<5}')} {col(sev_col[f.severity], f'{f.severity:<7}')} "
                     f"{col('35', f.rule)}{col('2', who)}")
        lines.append(f"         {f.message}")
        if snippet and f.snippet:
            lines.append(col("2", f"         > {f.snippet}"))
    cnt = {s: sum(1 for f in findings if f.severity == s) for s in SEV_RANK}
    bad_files = len({f.file for f in findings if f.severity in ("ERROR", "WARNING")})
    lines += ["", "─" * 60,
              f"Scanned: {stats['yaml']} YAML file(s) · Podman manifests: {stats['podman']} file(s) · "
              f"skipped (no Podman kind): {stats['skipped']}",
              f"Findings: {col(sev_col['ERROR'], str(cnt['ERROR']) + ' errors')}, "
              f"{col(sev_col['WARNING'], str(cnt['WARNING']) + ' warnings')}, "
              f"{cnt['INFO']} info  →  {bad_files} file(s) affected",
              f"Reference: Podman {DOC_VERSION} – {DOC_URL}"]
    if cnt["ERROR"] == 0 and cnt["WARNING"] == 0:
        lines.insert(-1, col("32;1", "No issues found ✔"))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=f"Lint Podman kube play manifests (YAML / YAML.J2) against the podman kube play {DOC_VERSION} documentation.")
    ap.add_argument("paths", nargs="*", default=["."], help="Files or directories to scan (default: current directory)")
    ap.add_argument("-x", "--exclude", action="append", default=[], metavar="GLOB",
                    help="Exclude a path, filename, or directory name (may be repeated)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Also show INFO findings")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("-o", "--output", help="Write the report to a file instead of stdout")
    ap.add_argument("--fail-on", choices=("error", "warning", "never"), default="error",
                    help="Exit with code 1 at or above this severity (default: error)")
    ap.add_argument("--all-kinds", action="store_true",
                    help="Also report files containing only unsupported Kubernetes kinds (Service, Ingress, ...)")
    ap.add_argument("--snippet", action="store_true",
                    help="Include source lines in reports (may expose sensitive values)")
    ap.add_argument("--no-color", action="store_true", help="Disable colored text output")
    a = ap.parse_args(argv)

    for p in a.paths:
        if not Path(p).exists():
            print(f"Path not found: {p}", file=sys.stderr)
            return 2
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if os.name == "nt":
        os.system("")  # ANSI-Farben in der Windows-Konsole aktivieren
    color = Col(sys.stdout.isatty() and not a.no_color and not a.output and "NO_COLOR" not in os.environ)

    stats = {"yaml": 0, "podman": 0, "skipped": 0}
    parsed: list[ParsedFile] = []
    for p, root in iter_files(a.paths, a.exclude, DEFAULT_SKIP_DIRS):
        stats["yaml"] += 1
        rel = p.relative_to(root).as_posix() if p.is_relative_to(root) else str(p)
        if Path(a.paths[0]).is_dir() and len(a.paths) > 1:
            rel = p.as_posix()
        pf = parse_file(p, rel, a.all_kinds)
        if pf is None:
            stats["skipped"] += 1
        else:
            parsed.append(pf)
    stats["podman"] = len(parsed)

    index = set()
    for pf in parsed:
        for ch in pf.chunks:
            d = ch.data
            if isinstance(d, LDict) and d.get("kind") in ("ConfigMap", "Secret", "PersistentVolumeClaim"):
                md = d.get("metadata")
                if isinstance(md, LDict) and isinstance(md.get("name"), str):
                    index.add((d["kind"], md["name"]))

    findings: list[Finding] = []
    for pf in parsed:
        analyze(pf, index, findings, a.all_kinds)

    min_sev = "INFO" if a.verbose else "WARNING"
    if a.format == "json":
        shown = [asdict(f) for f in findings if SEV_RANK[f.severity] >= SEV_RANK[min_sev]]
        if not a.snippet:
            for finding in shown:
                finding.pop("snippet")
        report = json.dumps({"podman_doc_version": DOC_VERSION, "stats": stats, "findings": shown}, indent=2, ensure_ascii=False)
    else:
        report = render_text(findings, stats, color, min_sev, a.snippet)

    if a.output:
        Path(a.output).write_text(report + "\n", encoding="utf-8")
        print(f"Report written to: {a.output}")
    else:
        print(report)

    if a.fail_on == "never":
        return 0
    limit = SEV_RANK["ERROR" if a.fail_on == "error" else "WARNING"]
    return 1 if any(SEV_RANK[f.severity] >= limit for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
