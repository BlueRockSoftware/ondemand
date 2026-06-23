#!/bin/bash

export ONDEMAND_USERNAME="$1"
if [ "${ONDEMAND_USERNAME}" = "" ]; then
  echo "Must specify username"
  exit 1
fi
HOOK_ENV="$2"
if [ "${HOOK_ENV}" = "" ]; then
  echo "Must specify hook.env path"
  exit 1
fi

set -e

# shellcheck disable=SC1090
source "$HOOK_ENV"
# shellcheck disable=SC2046
export $(grep -Ev "^#" "$HOOK_ENV" | cut -d= -f1)

export PATH=/usr/local/bin:/bin:$PATH
export NAMESPACE="${NAMESPACE_PREFIX}${ONDEMAND_USERNAME}"
export NFS_SERVER="${NFS_SERVER:-172.20.26.45}"
# Node subnet for the session NetworkPolicy. Defaults to the pod CIDR when a
# deployment sets no node CIDR, so network-policy.yaml never renders an empty
# ipBlock cidr (an invalid NetworkPolicy). See network-policy.yaml.
export NETWORK_POLICY_ALLOW_NODE_CIDR="${NETWORK_POLICY_ALLOW_NODE_CIDR:-$NETWORK_POLICY_ALLOW_CIDR}"
# API-server subnet for restricted sessions' egress NetworkPolicy. Independent
# of NODE_CIDR (which drives ingress) so allowing API egress doesn't loosen
# ingress. Defaults to the pod CIDR when unset, so deny-egress-restricted.yaml
# never renders an empty ipBlock cidr. See deny-egress-restricted.yaml.
export NETWORK_POLICY_ALLOW_API_CIDR="${NETWORK_POLICY_ALLOW_API_CIDR:-$NETWORK_POLICY_ALLOW_CIDR}"
# spec 043: network-policy.yaml scopes session ingress to the OOD portal
# namespace via $OOD_PORTAL_NAMESPACE (provided by the chart hook.env). If a
# stale hook.env omits it, fail loudly here rather than envsubst it to an empty
# string -- an empty namespaceSelector matches NO namespace, which would make
# every session unreachable through the portal (silent, cluster-wide outage).
if [ -z "${OOD_PORTAL_NAMESPACE:-}" ]; then
  echo "level=error msg=\"OOD_PORTAL_NAMESPACE unset; refusing to render the session NetworkPolicy. Update the OOD chart hook.env (spec 043).\""
  exit 1
fi
# shellcheck disable=SC2155
export TIMESTAMP=$(date +%s)

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
YAML_DIR="${BASEDIR}/yaml"
TMPFILE=$(mktemp "/tmp/k8-ondemand-bootstrap-${ONDEMAND_USERNAME}.XXXXXX")

{
  envsubst < "${YAML_DIR}/namespace.yaml"
  envsubst < "${YAML_DIR}/network-policy.yaml"
  envsubst < "${YAML_DIR}/deny-egress-restricted.yaml"
  envsubst < "${YAML_DIR}/deny-egress-locked.yaml"
  envsubst < "${YAML_DIR}/rolebinding.yaml"
} > "$TMPFILE"

if [ "$USE_POD_SECURITY_POLICY" = "true" ] ; then
  PASSWD=$(getent passwd "$ONDEMAND_USERNAME")
  if ! [[ "$PASSWD" =~ "${ONDEMAND_USERNAME}:"* ]]; then
    echo "level=error msg=\"Unable to perform lookup of user\" user=$ONDEMAND_USERNAME"
    exit 1
  fi
  UID=$(echo "$PASSWD" | cut -d':' -f3)
  GID=$(echo "$PASSWD" | cut -d':' -f4)
  export USER_UID=$UID
  export USER_GID=$GID
  envsubst < "${YAML_DIR}/pod-security-policy.yaml" >> "$TMPFILE"
fi

if [ "$USE_JOB_POD_REAPER" = "true" ] ; then
  envsubst < "${YAML_DIR}/job-pod-reaper.yaml" >> "$TMPFILE"
fi

kubectl apply -f "$TMPFILE"
rm -f "$TMPFILE"

if [ "$IMAGE_PULL_SECRET" != "" ]; then
  kubectl create secret generic "$IMAGE_PULL_SECRET" \
    --from-file=.dockerconfigjson="$REGISTRY_DOCKER_CONFIG_JSON" \
    --type=kubernetes.io/dockerconfigjson -n "$NAMESPACE" \
    -o yaml --dry-run=client | kubectl apply -f-
  kubectl patch serviceaccount default -n "$NAMESPACE" -p "{\"imagePullSecrets\": [{\"name\": \"${IMAGE_PULL_SECRET}\"}]}"
fi
