FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
# Writable runtime dirs for the unprivileged nginx user (cache + pid)
RUN mkdir -p /var/cache/nginx /run && chown -R nginx:nginx /var/cache/nginx /run /usr/share/nginx/html /etc/nginx/conf.d
EXPOSE 3000
USER nginx
CMD ["nginx", "-g", "daemon off;"]
