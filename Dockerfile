FROM node:20-bullseye-slim

WORKDIR /opt/application

COPY package*.json ./

RUN npm i

COPY . .
RUN npm run build

RUN chmod +x /opt/application/run.sh

EXPOSE 8000

CMD ["./run.sh"]