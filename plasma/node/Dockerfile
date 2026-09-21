FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
RUN npx tsc

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production NODE_OPTIONS=--max-old-space-size=96
COPY --from=build /app/package.json ./
COPY --from=build /app/dist ./dist
USER 1000
EXPOSE 8080
CMD ["node", "dist/node.js"]
