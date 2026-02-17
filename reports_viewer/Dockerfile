# Build Frontend
FROM node:18-alpine as frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Build Backend & Serve
FROM nginx:alpine

# Copy Nginx Configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy Frontend Build
COPY --from=frontend-builder /app/frontend/dist /usr/share/nginx/html

# Expose Port
EXPOSE 80

# Run
CMD ["nginx", "-g", "daemon off;"]
