# Use the official Node.js 18 image as the base
FROM node:18

# Create app directory
WORKDIR /app

# Copy package.json and package-lock.json (if available)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of your app's code
COPY . .

# App will run on port 3000
EXPOSE 3000

# Start the server
CMD ["node", "server.js"]
