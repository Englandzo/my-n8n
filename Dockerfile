FROM docker.n8n.io/n8nio/n8n:1.123.22
USER root
RUN cd /usr/local/lib/node_modules/n8n && npm install bcryptjs
USER node
