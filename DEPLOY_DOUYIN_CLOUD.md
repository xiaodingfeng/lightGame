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

兼容别名：

- `APP_ID` 或 `TT_APP_ID` 也可作为 `DOUYIN_APP_ID`
- `APP_SECRET`、`APPSECREAT`、`DOUYIN_APPSECREAT` 也可作为 `DOUYIN_APP_SECRET`
- `PAY_SALT` 也可作为 `DOUYIN_PAY_SALT`

容器启动日志会打印变量摘要，不会打印密钥原文。

## 本地验证

```bash
npm run build
PORT=8000 NODE_ENV=production DOUYIN_CLOUD=true node dist/server.js
```

## 探活检查

- `GET /ping`
- `GET /v1/ping`
