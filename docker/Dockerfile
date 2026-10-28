FROM node:latest
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY requirements.txt ./
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip python3-venv sqlite3 && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m pip install --no-cache-dir --break-system-packages -r requirements.txt
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]

