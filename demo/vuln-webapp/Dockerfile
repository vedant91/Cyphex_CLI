FROM node:20-alpine

WORKDIR /app

# Copy package files and install deps first (layer caching)
COPY package*.json ./
RUN npm install --no-audit --no-fund --omit=dev 2>/dev/null || npm install --no-audit --no-fund

# Copy source code
COPY . .

# The official node image ships a non-root "node" user — use it
RUN chown -R node:node /app
USER node

ENV PORT=3000
EXPOSE 3000

CMD ["node", "src/server.js"]