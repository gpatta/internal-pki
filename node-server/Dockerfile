# Stage 1: Use an official Node.js LTS (Long Term Support) image as a base.
# Using alpine makes the image significantly smaller.
FROM node:18-alpine AS base

# Create and define the working directory inside the container
WORKDIR /usr/src/app

# --- Security Best Practice ---
# Create a dedicated, non-root user and group for the application
# RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy package.json and package-lock.json first to leverage Docker layer caching
# COPY --chown=appuser:appgroup package*.json ./
COPY package*.json ./

# Install app dependencies
RUN npm install

# Copy the rest of the application source code into the container
# COPY --chown=appuser:appgroup . .
COPY . .

# Switch to the non-root user
# USER appuser

# Expose the port the server will listen on
EXPOSE ${PORT}

# Define the command to run the application when the container starts.
# Using the exec form allows signals (like SIGTERM) to be passed to the Node process.
CMD [ "node", "server.js" ]