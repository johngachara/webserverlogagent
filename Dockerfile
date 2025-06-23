FROM node:current-slim
WORKDIR /logagent
COPY package.json .
RUN npm install --verbose
RUN apt-get update && apt-get install -y iptables
COPY . .
CMD ["npm","start"]