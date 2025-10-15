#!/bin/bash

echo "🔧 Installing Julia for Net-Zilla AI..."

# Detect platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    wget https://julialang-s3.julialang.org/bin/linux/x64/1.9/julia-1.9.3-linux-x86_64.tar.gz
    tar -xzf julia-1.9.3-linux-x86_64.tar.gz
    sudo mv julia-1.9.3 /opt/
    sudo ln -s /opt/julia-1.9.3/bin/julia /usr/local/bin/julia
    
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    brew install julia
    
elif [[ "$OSTYPE" == "msys" ]]; then
    # Windows (Git Bash)
    echo "Please download Julia from: https://julialang.org/downloads/"
    echo "And add it to your PATH"
else
    echo "Unsupported platform: $OSTYPE"
    exit 1
fi

echo "✅ Julia installation complete!"
