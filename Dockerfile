FROM node:18-alpine

WORKDIR /app

# Install global dependencies
RUN npm install -g npm@latest

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source files
COPY . .

# Build the CLI
RUN npm run build

# Install the CLI globally
RUN npm install -g .

# Clean up
RUN rm -rf /var/lib/apt/lists/*

# Set entrypoint
ENTRYPOINT ["sh"]
