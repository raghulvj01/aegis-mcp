from __future__ import annotations

import json
import subprocess
from typing import Any


def k8s_security_audit(namespace: str = "") -> list[dict[str, Any]]:
    findings = []

    cmd_base = ["kubectl", "get"]
    if namespace:
        ns_args = ["-n", namespace]
    else:
        ns_args = ["-A"]

    try:
        pods_result = subprocess.check_output(
            cmd_base + ["pods"] + ns_args + ["-o", "json"],
            stderr=subprocess.STDOUT,
            text=True,
        )
        pods_payload = json.loads(pods_result)
    except Exception as exc:
        print(f"Warning: Failed to get pods: {exc}")
        pods_payload = {"items": []}

    try:
        services_result = subprocess.check_output(
            cmd_base + ["svc"] + ns_args + ["-o", "json"],
            stderr=subprocess.STDOUT,
            text=True,
        )
        svcs_payload = json.loads(services_result)
    except Exception as exc:
        print(f"Warning: Failed to get services: {exc}")
        svcs_payload = {"items": []}

    try:
        roles_result = subprocess.check_output(
            cmd_base + ["clusterrolebindings", "-o", "json"],
            stderr=subprocess.STDOUT,
            text=True,
        )
        crb_payload = json.loads(roles_result)
    except Exception as exc:
        print(f"Warning: Failed to get clusterrolebindings: {exc}")
        crb_payload = {"items": []}

    # Parse pods
    for pod in pods_payload.get("items", []):
        metadata = pod.get("metadata", {})
        pod_name = metadata.get("name", "unknown")
        pod_ns = metadata.get("namespace", "unknown")
        spec = pod.get("spec", {})

        # Check hostNetwork
        if spec.get("hostNetwork") is True:
            findings.append({
                "type": "hostNetwork",
                "severity": "HIGH",
                "resource": f"Pod/{pod_ns}/{pod_name}",
                "message": "Pod is using host network."
            })

        # Check privileged containers
        for container in spec.get("containers", []):
            sec_ctx = container.get("securityContext", {})
            if sec_ctx.get("privileged") is True:
                findings.append({
                    "type": "privileged_container",
                    "severity": "CRITICAL",
                    "resource": f"Pod/{pod_ns}/{pod_name}",
                    "message": f"Container '{container.get('name')}' is running as privileged.",
                })

    # Parse services
    for svc in svcs_payload.get("items", []):
        metadata = svc.get("metadata", {})
        svc_name = metadata.get("name", "unknown")
        svc_ns = metadata.get("namespace", "unknown")
        spec = svc.get("spec", {})

        if spec.get("type") == "NodePort":
            findings.append({
                "type": "exposed_nodeport",
                "severity": "MEDIUM",
                "resource": f"Service/{svc_ns}/{svc_name}",
                "message": "Service is exposed via NodePort."
            })

    # Parse cluster role bindings
    for crb in crb_payload.get("items", []):
        metadata = crb.get("metadata", {})
        crb_name = metadata.get("name", "unknown")
        role_ref = crb.get("roleRef", {})

        if role_ref.get("name") == "cluster-admin":
            for subj in crb.get("subjects", []):
                if subj.get("kind") == "ServiceAccount":
                    findings.append({
                        "type": "cluster_admin_sa",
                        "severity": "CRITICAL",
                        "resource": f"ClusterRoleBinding/{crb_name}",
                        "message": f"ServiceAccount '{subj.get('namespace')}/{subj.get('name')}' is bound to cluster-admin."
                    })

    return findings
