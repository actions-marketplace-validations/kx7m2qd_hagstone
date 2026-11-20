FROM node:22-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
# expect: ds-0002
USER root
CMD ["node", "server.js"]
