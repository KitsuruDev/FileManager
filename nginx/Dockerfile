FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/nginx.conf

# сертификаты будут созданы в CI и положены сюда перед сборкой
COPY certs/ /etc/nginx/certs/

EXPOSE 443