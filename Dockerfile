FROM node:24-slim
WORKDIR /logagent
RUN apt-get update && apt-get upgrade -y && apt-get install -y iptables
COPY package.json .
RUN npm install --verbose
COPY . .
CMD ["npm","start"]