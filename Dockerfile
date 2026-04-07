FROM node:20-bullseye-slim

WORKDIR /opt/application

COPY package*.json ./

# 核心：跳过原生模块编译，只装纯JS依赖
RUN npm ci --ignore-scripts

COPY . .
RUN npm run build

RUN chmod +x /opt/application/run.sh

EXPOSE 8000

CMD ["./run.sh"]