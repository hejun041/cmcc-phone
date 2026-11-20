#!/bin/sh
# 一键发布：拉取最新源码 → 构建镜像 → 切换 compose 镜像 → 重启 → 健康检查
#
# 用法：
#   sh scripts/sync-and-deploy.sh [镜像tag]
#
# 可用环境变量覆盖默认值（NAS 上的实际路径）：
#   SRC     源码目录（git clone），默认 /vol1/1000/cmcc-phone-src
#   APP     部署目录（含 docker-compose.yml 与 data/），默认 /vol1/1000/cmcc-phone
#   MIRROR  GitHub 镜像源前缀，默认 https://ghfast.top/
#   SERVICE 容器名，默认 cmcc-cloudphone-manager
set -eu
SRC=${SRC:-/vol1/1000/cmcc-phone-src}
APP=${APP:-/vol1/1000/cmcc-phone}
MIRROR=${MIRROR:-https://ghfast.top/}
SERVICE=${SERVICE:-cmcc-cloudphone-manager}
TAG=${1:-cmcc-phone:deploy-$(date +%Y%m%d%H%M)}
HEALTH_URL=${HEALTH_URL:-http://127.0.0.1:8680/api/health}

cd "$SRC"
# 国内直连 github.com 经常超时：优先走镜像，失败再退回 origin
if timeout 60 git fetch mirror main:refs/remotes/origin/main 2>/dev/null; then
  echo "fetched via mirror"
elif timeout 60 git fetch origin main 2>/dev/null; then
  echo "fetched via origin"
else
  echo "!! 拉取失败：继续使用当前源码 $(git rev-parse --short HEAD)" >&2
fi
git merge --ff-only origin/main
echo "源码版本: $(git log --oneline -1)"

docker build -t "$TAG" "$SRC"

cd "$APP"
cp docker-compose.yml "backups/docker-compose.yml.$(date +%Y%m%dT%H%M%S)"
sed -i "s|image: cmcc-phone:.*|image: $TAG|" docker-compose.yml
docker compose up -d

# 等待健康检查通过（最多 60 秒）
i=0
while [ $i -lt 30 ]; do
  if curl -fsS --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
    break
  fi
  i=$((i+1))
  sleep 2
done
docker ps --filter "name=$SERVICE" --format "{{.Image}}|{{.Status}}"
curl -fsS --max-time 5 "$HEALTH_URL"
echo
