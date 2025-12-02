# deployments/docker/Dockerfile
FROM golang:1.21-alpine AS builder

# Install Julia in the builder stage to potentially compile Julia dependencies
# For Alpine, Julia can be installed from community repositories or manually.
# Manual installation is more robust for specific versions or if not in repos.
# Here, assuming 'julia' is in alpine edge or a specific version is downloaded.
# A more robust solution might involve a separate Julia builder image or downloading Julia binary.
# For simplicity, let's assume it's available via apk add for now, or use a pre-built image.
RUN apk add --no-cache julia # This might install an older Julia or fail if not in main repos.
# A more robust Julia setup:
# ENV JULIA_VERSION 1.9.3
# RUN wget -q "https://julialang-s3.julialang.org/bin/alpine/x66_64/${JULIA_VERSION%.*}/julia-${JULIA_VERSION}-alpine-x64.tar.gz" -O /tmp/julia.tar.gz && \
#     tar -xzf /tmp/julia.tar.gz -C /opt && \
#     rm /tmp/julia.tar.gz
# ENV PATH="/opt/julia-${JULIA_VERSION}/bin:${PATH}"

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Correctly build the main CLI application
RUN CGO_ENABLED=0 GOOS=linux go build -o netzilla ./cmd/netzilla


FROM alpine:latest
# Install necessary packages for Julia runtime (if not included in base alpine or if a custom Julia build is used)
# For running Julia scripts, often need ca-certificates, sometimes git, etc.
RUN apk add --no-cache ca-certificates julia # Add julia to the runtime image too

# Create a non-root user for security
RUN adduser -D nonroot
USER nonroot
WORKDIR /home/nonroot/

# Copy the built Go executable
COPY --from=builder /app/netzilla .

# Copy Julia scripts and ML models
# Assuming models and scripts are in internal/ai based on current project structure
COPY --from=builder /app/internal/ai/julia_agent.jl ./internal/ai/
COPY --from=builder /app/internal/ai/orchestrator.jl ./internal/ai/
COPY --from=builder /app/internal/ai/sms_analyzer.jl ./internal/ai/ # Assuming this exists
# Copy ML models (e.g., .jlso files)
COPY --from=builder /app/ml/models/ ./ml/models/ # Assuming this path based on config defaults

# It is better to rely on environment variables set during deployment for configuration
# COPY configs/ ./configs/

EXPOSE 8080 # This port is for potential web API if enabled, otherwise not strictly needed for CLI

# Set environment variables for Julia scripts to find models
# These should match the config defaults or be overridden at runtime
ENV NETZILLA_AI_JULIA_PATH="julia"
ENV NETZILLA_AI_ML_MODELS_PATH="/home/nonroot/ml/models" # Update to internal path in docker

# Command to run the CLI application
CMD ["./netzilla"]
