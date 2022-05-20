#Staging
FROM python:3.9-alpine AS stage
RUN  apk add build-base
RUN  apk add --no-cache \
        libressl-dev \
        musl-dev \
        libffi-dev 
COPY requirements.txt ./
RUN  pip install -r requirements.txt --user

#Production
FROM python:3.9-alpine
COPY --from=stage /root/.local /root/.local
COPY main.py .

ENV PATH=/root/.local/bin:$PATH
CMD  [ "python", "main.py" ]