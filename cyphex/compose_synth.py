import os
import yaml
from typing import Dict, Any

def _generate_dockerfile_content(app_info: Dict[str, Any]) -> str:
    """Generate a Dockerfile for the target app if one doesn't exist."""
    lang = app_info.get("language", "unknown")
    port = app_info.get("port", 3000)
    
    if lang == "node":
        return f"""FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN chown -R node:node /app
USER node
ENV PORT={port}
EXPOSE {port}
CMD ["npm", "start"]
"""
    elif lang == "python":
        return f"""FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || pip install flask
COPY . .
RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 10001 sandboxuser \\
    && chown -R sandboxuser:sandboxuser /app
USER sandboxuser
ENV PORT={port}
EXPOSE {port}
CMD ["python", "app.py"]
"""
    elif lang == "java":
        return f"""FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app
COPY . .
RUN ./mvnw spring-boot:run || ./gradlew bootRun || echo "Java fallback"
RUN addgroup -S sandboxuser && adduser -S sandboxuser -G sandboxuser \\
    && chown -R sandboxuser:sandboxuser /app
USER sandboxuser
ENV PORT={port}
EXPOSE {port}
CMD ["java", "-jar", "app.jar"]
"""
    elif lang == "go":
        return f"""FROM golang:1.21-alpine
WORKDIR /app
COPY . .
RUN go build -o main .
RUN addgroup -S sandboxuser && adduser -S sandboxuser -G sandboxuser \\
    && chown -R sandboxuser:sandboxuser /app
USER sandboxuser
ENV PORT={port}
EXPOSE {port}
CMD ["./main"]
"""
    elif lang == "static":
        return f"""FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 10001 sandboxuser \\
    && chown -R sandboxuser:sandboxuser /app
USER sandboxuser
ENV PORT={port}
EXPOSE {port}
CMD ["python", "-m", "http.server", "{port}"]
"""
    else:
        # Fallback to a python server serving static files or executing python
        return f"""FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 10001 sandboxuser \\
    && chown -R sandboxuser:sandboxuser /app
USER sandboxuser
ENV PORT={port}
EXPOSE {port}
CMD ["python", "-m", "http.server", "{port}"]
"""

def synthesize_compose(source_dir: str, manifest: Dict[str, Any]) -> str:
    """
    Generate docker-compose.sandbox.yml and any missing Dockerfiles.
    Returns path to the generated docker-compose.sandbox.yml.
    """
    compose_content = {
        "version": "3.8",
        "services": {},
        "networks": {
            "cyphex-net": {
                "driver": "bridge"
            }
        }
    }
    
    services = manifest.get("services", {})
    for srv_name, srv_data in services.items():
        rel_path = srv_data["path"]
        abs_path = os.path.join(source_dir, rel_path)
        
        # Determine Dockerfile
        existing_dockerfile = os.path.join(abs_path, "Dockerfile")
        cyphex_dockerfile = os.path.join(abs_path, "Dockerfile.cyphex")
        
        dockerfile_to_use = "Dockerfile"
        
        if not os.path.exists(existing_dockerfile):
            # Generate Dockerfile.cyphex
            with open(cyphex_dockerfile, "w") as f:
                f.write(_generate_dockerfile_content(srv_data))
            dockerfile_to_use = "Dockerfile.cyphex"
            
        port = srv_data.get("port", 3000)
        
        compose_content["services"][srv_name] = {
            "build": {
                "context": rel_path if rel_path != "." else ".",
                "dockerfile": dockerfile_to_use
            },
            "networks": ["cyphex-net"],
            "ports": [
                f"127.0.0.1:0:{port}" # Docker assigns random host port
            ],
            "environment": [
                f"PORT={port}"
            ],
            # Hardening guarantees
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "deploy": {
                "resources": {
                    "limits": {
                        "memory": "512m",
                        "cpus": "1"
                    }
                }
            },
            "pids_limit": 200
        }
        
    compose_path = os.path.join(source_dir, "docker-compose.sandbox.yml")
    with open(compose_path, "w") as f:
        yaml.dump(compose_content, f, sort_keys=False)
        
    return compose_path
