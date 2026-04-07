# 使用国内加速镜像源 + 不安装任何编译工具
FROM node:20-bullseye-slim

WORKDIR /opt/application

COPY package*.json ./

# 关键：跳过 sqlite3 编译，直接安装纯 JS 版
RUN npm install better-sqlite3 --force
RUN npm ci --force

COPY . .
RUN npm run build

RUN chmod +x /opt/application/run.sh

EXPOSE 8000

CMD ["./run.sh"]