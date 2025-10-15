#!/bin/bash

# Update Helm dependencies
echo "Updating Helm dependencies..."
helm dependency update

# Check for dependency issues
echo "Checking dependency status..."
helm dependency list

# Build dependencies
echo "Building dependencies..."
helm dependency build

echo "Dependencies updated successfully!"
