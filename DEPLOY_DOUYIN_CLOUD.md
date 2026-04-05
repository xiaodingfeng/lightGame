# 抖音云开发环境部署说明

本目录已经补齐抖音云模板部署需要的关键文件：

- `Dockerfile`
- `run.sh`

服务运行约束已经同步到代码：

- 默认监听 `8000`
- 提供 `/ping`
- 提供 `/v1/ping`
- SQLite 默认落到 `/data/database.sqlite`

## 建议环境变量

- `JWT_SECRET`
- `DOUYIN_APP_ID`
- `DOUYIN_APP_SECRET`
- `DOUYIN_PAY_SALT`
- `NODE_ENV=production`
- `DOUYIN_CLOUD=true`
- `PORT=8000`
- `DB_PATH=/data/database.sqlite`

## 本地验证

```bash
npm run build
PORT=8000 NODE_ENV=production DOUYIN_CLOUD=true node dist/server.js
```

## 探活检查

- `GET /ping`
- `GET /v1/ping`
