FROM alpine:3.19
COPY secrets.env /app/secrets.env
RUN cat /app/secrets.env > /app/config && rm /app/secrets.env
CMD ["sh"]
