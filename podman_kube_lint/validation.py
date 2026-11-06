"""Validate Podman manifest fields."""

import base64
import binascii
import re

from .findings import Ctx
from .rules import (CONTAINER, DNS_LABEL, DNS_SUB, DOC_VERSION, HOSTPATH_TYPES,
                    KNOWN_POD_ANN, META_KEYS, PH, POD_SPEC, PVC_ANNOTATIONS,
                    PVC_SPEC, QTY, SUPPORTED_KINDS, SUPPORTED_VOLUMES, TOP, WORKLOAD_SPEC)
from .yaml_loader import LDict, LList

def kl(d, k):
    return d.klines.get(k, d.line) if isinstance(d, LDict) else 0


def is_ph(v):
    return isinstance(v, str) and PH in v


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def tn(v):
    if v is None: return "null"
    if isinstance(v, bool): return "Boolean"
    if isinstance(v, int): return "integer"
    if isinstance(v, float): return "float"
    if isinstance(v, str): return "string"
    if isinstance(v, list): return "list"
    if isinstance(v, dict): return "mapping"
    return type(v).__name__


TYPES = {
    "str": (lambda v: isinstance(v, str), "a string"),
    "int": (is_int, "an integer"),
    "bool": (lambda v: isinstance(v, bool), "a boolean"),
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
