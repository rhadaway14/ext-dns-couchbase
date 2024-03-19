#!/bin/bash


################################################################
# TO DO:
# HANDLE IAM POLICY CREATION
# HANDLE DOMAIN CHECKS AND ALT-NAMES
# ADD SUBDOMAIN CONTROLS
# INCLUDE HELM REPO DL AND UPDATE
# UPDATE THE EXTERNAL-DNS MANIFEST WITH YQ
# MAYBE INCLUDE AN AO VERSION DL FUNCTION TO PULL DESIGNATED VERSION OF COUCHBASE
################################################################

# Check dependencies

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "AWS CLI is not installed. Please install it before running this script."
    exit 1
fi

# Check if eksctl is installed
if ! command -v eksctl &> /dev/null; then
    echo "eksctl is not installed. Please install it before running this script."
    exit 1
fi

# Check if Helm is installed
if ! command -v helm &> /dev/null; then
    echo "Helm is not installed. Please install it before running this script."
    exit 1
fi

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo "kubectl is not installed. Please install it before running this script."
    exit 1
fi

# Check if Git is installed
if ! command -v git &> /dev/null; then
    echo "Git is not installed. Please install it before running this script."
    exit 1
fi

# Check if yq is installed
if ! command -v yq &> /dev/null; then
    echo "YQ is not installed. Please install it before running this script."
    exit 1
fi

# Default values
defaultNodeType="t2.medium"
defaultNodeNumber=3
defaultVersion="1.27"
defaultNamespace="demo"
defaultUsername="Administrator"
defaultPassword="couchbase"

# Initialize variables with default values
nodeType="$defaultNodeType"
nodeNumber="$defaultNodeNumber"
version="$defaultVersion"
namespace="$defaultNamespace"
username="$defaultUsername"
password="$defaultPassword"

# Display usage information
usage() {
    echo "To run this script, AWS CLI must be installed and have permissions to create resources, and roles"
    echo "Usage: $0 -c|--cluster <clusterName> -r|--region <region> -d|--domain <domain>"
    echo "      -t|--type <nodeType> -s|--size <nodeNumber> -v|--version <version>"
    echo "      -u|--username <username> -p|--password <password> -n|--namespace <namespace>"
    echo ""
    echo ""
    echo "  -c, --cluster   The name of the EKS cluster (required)."
    echo "  -r, --region    The AWS region to deploy EKS (required)."
    echo "  -d, --domain    The domain to use for external-dns (required)."
    echo "  -u, --username  The username of the couchbase cluser (default: $defaultUsername)."
    echo "  -p, --password  The password of the couchbase cluser (default: $defaultPassword)."
    echo "  -t, --type      The type of node for the EKS cluster (default: $defaultNodeType)."
    echo "  -s, --size      The number of nodes to deploy in the EKS cluster (default: $defaultNodeNumber). Minimum nodes cannot be less than 0."
    echo "  -v, --version   The version of Kubernetes for the EKS cluster (default: $defaultVersion)."
    echo "  -n, --namespace The kubernetes namespace to deploy couchbase into (default: $defaultNamespace)."
    echo "  -h, --help      Display this help message"

    exit 1
}

# functions

# Wait for a Kubernetes deployment to be ready
wait_for_deployment() {
    local deployment_name="$1"
    local namespace="$2"
    
    echo "Waiting for deployment $deployment_name in namespace $namespace to be ready..."

    # Poll the deployment status until all replicas are ready
    while true; do
        local replicas_ready=$(kubectl get deployment "$deployment_name" -n "$namespace" -o jsonpath='{.status.readyReplicas}')
        local replicas_desired=$(kubectl get deployment "$deployment_name" -n "$namespace" -o jsonpath='{.spec.replicas}')
        
        if [[ "$replicas_ready" -eq "$replicas_desired" ]]; then
            echo "Deployment $deployment_name is ready."
            break
        else
            echo "Waiting for $replicas_ready out of $replicas_desired replicas to be ready..."
            sleep 5
        fi
    done
}

wait_for_cluster() {
    local cluster_name="$1"
    local namespace="$2"
    
    echo "Waiting for cluster $cluster_name in namespace $namespace to be ready..."
    while true; do
        kubectl get couchbasecluster -n "$namespace" -o jsonpath='{.items[0].status.members}'
        local replicas_ready=$(kubectl get couchbasecluster -n "$namespace" -o jsonpath='{range .items[0].status.members.ready[*]}{@}{"\n"}{end}' | wc -l)
        local replicas_desired=$(kubectl get couchbasecluster -n "$namespace" -o jsonpath='{.items[0].spec.servers[0].size}')
        if [[ "$replicas_ready" -eq "$replicas_desired" ]]; then
            echo "Deployment $cluster_name is ready."
            break
        else
            echo "Waiting for $replicas_ready out of $replicas_desired replicas to be ready..."
            sleep 5
        fi
    done
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--cluster)
            clusterName="$2"
            shift 2
            ;;
        -r|--region)
            region="$2"
            shift 2
            ;;
        -t|--type)
            nodeType="$2"
            shift 2
            ;;
        -s|--size)
            nodeNumber="$2"
            shift 2
            ;;
        -v|--version)
            version="$2"
            shift 2
            ;;
        -d|--domain)
            domain="$2"
            shift 2
            ;;
        -n|--namespace)
            namespace="$2"
            shift 2
            ;;
        -p|--password)
            password="$2"
            shift 2
            ;;
        -u|--username)
            username="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Invalid option: $1"
            usage
            ;;
    esac
done

# Check if min node will be less than 0
if [ "$nodeNumber" -le 0 ]; then
    echo "The number of nodes (-n) must be a positive integer."
    usage
fi

# Check for required variables
if [ -z "$clusterName" ] || [ -z "$region" ] || [ -z "$domain" ]; then
    echo "You must provide values for the clusterName and region"
    usage
fi

# Create EKS Cluster
eksctl create cluster \
 --name $clusterName \
 --region $region \
 --zones ${region}a,${region}b,${region}c \
 --node-type $nodeType \
 --nodes $nodeNumber \
 --nodes-min $((nodeNumber - 1)) \
 --nodes-max $((nodeNumber + 1)) \
 --version $version

wait

if [ $? -eq 0 ]; then
    # If the eksctl command was successful, run the aws eks update-kubeconfig command
    aws eks --region $region update-kubeconfig --name $clusterName

    wait
    
    ###################### ADD NEW IAM POLICY HERE
    ###################### NEED A FUNCTION TO CREATE THIS IF IT HASN"T BEEN CREATED YET

    kubectl create namespace $namespace

    #Associate OIDC provider with cluster
    eksctl utils associate-iam-oidc-provider \
    --cluster $clusterName --approve

    # Create IAM service account
    eksctl create iamserviceaccount \
    --cluster $clusterName \
    --name "external-dns" \
    --namespace $namespace \
    --attach-policy-arn arn:aws:iam::205832703745:policy/AllowExternalDNSUpdates \
    --approve
else
    echo "Error: eksctl command failed."
fi

wait

# get eks vpc
vpc_id=$(aws eks describe-cluster --name $clusterName --query "cluster.resourcesVpcConfig.vpcId" --output text)

#create hosted zone
aws route53 create-hosted-zone \
  --name xdcr.com \
  --vpc "VPCRegion=$region,VPCId=$vpc_id" \
  --caller-reference $(date +%s)

wait

# Create TLS Certificates
mkdir rsa
git clone https://github.com/OpenVPN/easy-rsa ./rsa
wait
echo "yes" | ./rsa/easyrsa3/easyrsa init-pki
wait
echo "default" | ./rsa/easyrsa3/easyrsa build-ca nopass 
wait

# TODO: try to make all the sa-names parameterized 

echo "yes" | ./rsa/easyrsa3/easyrsa --subject-alt-name="DNS:*.$clusterName,DNS:*.$clusterName.$namespace,\
DNS:*.$clusterName.$namespace.svc,DNS:*.$namespace.svc,DNS:$clusterName-srv,\
DNS:$clusterName-srv.$namespace,DNS:$clusterName-srv.$namespace.svc,DNS:localhost,\
DNS:*.$clusterName.cbdemo.$domain,DNS:*.cbdemo.$domain,DNS:*.$clusterName.demo.svc.cluster.local, \
DNS:*.$clusterName-srv.$namespace.svc.cluster.local" \
build-server-full couchbase-server nopass

# Create secrets
kubectl create secret tls couchbase-server-ca \
  --cert ./pki/ca.crt \
  --key ./pki/private/ca.key \
  -n $namespace

wait

kubectl create secret tls couchbase-server-tls \
  --cert ./pki/issued/couchbase-server.crt \
  --key ./pki/private/couchbase-server.key \
  -n $namespace

#cleanup
rm ./rsa -rf
rm ./pki -rf

helm repo add couchbase https://couchbase-partners.github.io/helm-charts/
helm repo update
helm install couchbase --set cluster.name=$clusterName couchbase/couchbase-operator --namespace $namespace

wait_for_cluster $clusterName $namespace
wait

# kubectl delete couchbasecluster $clusterName -n $namespace

kubectl --namespace $namespace create -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: external-dns
rules:
- apiGroups: [""]
  resources: ["services","endpoints","pods"]
  verbs: ["get","watch","list"]
- apiGroups: ["extensions","networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get","watch","list"]
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get","watch","list"]
EOF


kubectl --namespace $namespace create -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: external-dns-viewer
  labels:
    app.kubernetes.io/name: external-dns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: external-dns
subjects:
  - kind: ServiceAccount
    name: external-dns
    namespace: $namespace
EOF

# ////////external-dns deployment goes here//////////////

wait

# Create initial username and password
encodedUsername=$(echo -n "$username" | base64)
encodedPassword=$(echo -n "$password" | base64)

kubectl --namespace "$namespace" create secret generic cb-example-auth --from-literal=username="$encodedUsername" --from-literal=password="$encodedPassword"

kubectl get couchbasecluster $clusterName -n $namespace -o yaml > cb-helm-output.yaml
wait

###############################################################
# testing private
# - --aws-zone-type=public -> private 
# - --domain-filter=$domain -> xdcr.com
# value: $region -> us-east-1
########################################################
# Deploy the Public-External-DNS
kubectl --namespace $namespace create -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
  labels:
    app.kubernetes.io/name: external-dns
spec:
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: external-dns
  template:
    metadata:
      labels:
        app.kubernetes.io/name: external-dns
    spec:
      serviceAccountName: external-dns
      containers:
        - name: external-dns
          image: registry.k8s.io/external-dns/external-dns:v0.13.5
          args:
            - --source=service
            - --source=ingress
            - --domain-filter=xdcr.com # will make ExternalDNS see only the hosted zones matching provided domain, omit to process all available hosted zones
            - --provider=aws
            - --policy=upsert-only # would prevent ExternalDNS from deleting any records, omit to enable full synchronization
            - --aws-zone-type=private # only look at public hosted zones (valid values are public, private or no value for both)
            - --registry=txt
            - --txt-owner-id=external-dns
          env:
            - name: AWS_DEFAULT_REGION
              value: us-east-1 # change to region where EKS is installed
EOF

# Deploy the Private-External-DNS
#kubectl --namespace $namespace create -f - <<EOF
#apiVersion: apps/v1
#kind: Deployment
#metadata:
#  name: external-dns-2
#  labels:
#    app.kubernetes.io/name: external-dns
#spec:
#  strategy:
#    type: Recreate
#  selector:
#    matchLabels:
#      app.kubernetes.io/name: external-dns
#  template:
#    metadata:
#      labels:
#        app.kubernetes.io/name: external-dns
#    spec:
#      serviceAccountName: external-dns
#      containers:
#        - name: external-dns
#          image: registry.k8s.io/external-dns/external-dns:v0.13.5
#          args:
#            - --source=service
#            - --source=ingress
#            - --domain-filter=xdcr.com # will make ExternalDNS see only the hosted zones matching provided domain, omit to process all available hosted zones
#            - --provider=aws
#            - --policy=upsert-only # would prevent ExternalDNS from deleting any records, omit to enable full synchronization
#            - --aws-zone-type=private # only look at public hosted zones (valid values are public, private or no value for both)
#            - --registry=txt
#            - --txt-owner-id=external-dns
#          env:
#            - name: AWS_DEFAULT_REGION
#              value: $region # change to region where EKS is installed
#EOF

yq eval '.spec.networking.adminConsoleServiceType = "LoadBalancer" |
.spec.networking.adminConsoleServiceTemplate.spec.type = "LoadBalancer" |
.spec.networking.exposedFeatureServiceType = "LoadBalancer" |
.spec.networking.exposedFeatureServiceTemplate.spec.type = "LoadBalancer" |
.spec.networking += {"dns": {"domain": "cbdemo.'"$domain"'"}, 
"tls": {"allowPlainTextCertReload": false, "passphrase": {}, "rootCAs": ["couchbase-server-ca"], 
"secretSource": {"serverSecretName": "couchbase-server-tls"}}}
' cb-helm-output.yaml > new-cluster-copy.yaml


#yq eval '.spec.networking.adminConsoleServiceType = "LoadBalancer" |
#.spec.networking.adminConsoleServiceTemplate.spec.type = "LoadBalancer" |
#.spec.networking.exposedFeatureServiceType = "LoadBalancer" |
#.spec.networking.exposedFeatureServiceTemplate.spec.type = "LoadBalancer" |
#.spec.security.adminSecret = "cb-example-auth" |
#.spec.networking += {"dns": {"domain": "cbdemo.'"$domain"'"}, 
#"tls": {"allowPlainTextCertReload": false, "passphrase": {}, "rootCAs": ["couchbase-server-ca"], 
#"secretSource": {"serverSecretName": "couchbase-server-tls"}, "tlsMinimumVersion": "TLS1.2"}}
#' cb-helm-output.yaml > new-cluster-copy.yaml

kubectl replace -f new-cluster-copy.yaml -n $namespace --force
# wait




echo "Deployment Complete"
