# Build Frontend
FROM node:18-alpine as frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Build Backend & Serve
FROM python:3.9-slim

WORKDIR /app

# Install Backend Dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Backend Code
COPY backend/ .

# Copy Frontend Build
COPY --from=frontend-builder /app/frontend/dist /app/static

# Expose Port
EXPOSE 80

# Run
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
