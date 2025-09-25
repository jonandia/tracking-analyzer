FROM ghcr.io/puppeteer/puppeteer:21.0.0

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY . .

ENV NODE_ENV=production
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

CMD ["node", "server.js"]