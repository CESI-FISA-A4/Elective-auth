FROM node:19.7-slim
WORKDIR /app
COPY . .
RUN npm install
RUN npm uninstall bcrypt
RUN npm install bcrypt
EXPOSE 3000
CMD ["npm", "run", "start"]