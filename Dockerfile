FROM node:lts-slim
WORKDIR /logagent
COPY package.json .
RUN npm install --verbose
COPY . .
CMD ["npm","start"]