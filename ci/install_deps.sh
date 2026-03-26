export DESIRED_VERSION="v3.5.4"
set -eux
HELM_INSTALL_DIR=/bin
curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
