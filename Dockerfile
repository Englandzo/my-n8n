FROM docker.n8n.io/n8nio/n8n:1.123.22
USER root
RUN npm install -g bcryptjs
USER node
