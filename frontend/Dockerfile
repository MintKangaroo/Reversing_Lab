FROM node:20.20.2-alpine

RUN addgroup -S rlab && adduser -S -G rlab rlab
WORKDIR /workspace/frontend
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN chown -R rlab:rlab /workspace/frontend

USER rlab
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
