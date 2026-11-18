# tavern-auth-gateway

浏览器登录、会话 Cookie 与反向代理。

通过 Dockerfile 构建。启动时从环境注入 ST_AUTH_USERNAME、ST_AUTH_PASSWORD 和 ST_AUTH_COOKIE_SECRET，按部署设置上游；代码仓库不持有其值。
