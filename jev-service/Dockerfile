FROM node:22-alpine
WORKDIR /app
COPY package.json classifier.mjs server.mjs ./
USER node
ENV NODE_ENV=production PORT=8091 BIND_HOST=0.0.0.0
EXPOSE 8091
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD node -e "fetch('http://127.0.0.1:8091/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.mjs"]
