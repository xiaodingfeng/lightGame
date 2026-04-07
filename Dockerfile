FROM node:20-bullseye-slim

# 安装 sqlite3 编译必须的依赖：python3 make g++
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/application

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

RUN chmod +x /opt/application/run.sh

EXPOSE 8000

CMD ["./run.sh"]