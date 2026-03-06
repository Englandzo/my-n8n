FROM docker.n8n.io/n8nio/n8n:1.123.22
USER root
RUN mkdir -p /usr/local/lib/node_modules/n8n/node_modules && cd /usr/local/lib/node_modules/n8n/node_modules && npm install bcryptjs --no-save --force
USER node
