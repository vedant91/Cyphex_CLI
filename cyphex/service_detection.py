import os
import json
import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

@dataclass
class ServiceSignature:
    id: str
    match_files: List[str]
    match_contains: Dict[str, str] = field(default_factory=dict)
    roles: List[str] = field(default_factory=list)
    language: str = ""
    protocol: str = "http"
    port_hint: int = 3000
    dockerfile_template: str = ""
    agents: List[str] = field(default_factory=list)

SIGNATURES = [
    # JavaScript / TypeScript
    ServiceSignature(
        id="nextjs",
        match_files=["package.json", "next.config.js"],
        roles=["frontend", "backend"],
        language="node",
        port_hint=3000,
    ),
    ServiceSignature(
        id="nestjs",
        match_files=["package.json", "nest-cli.json"],
        roles=["backend"],
        language="node",
        port_hint=3000,
    ),
    ServiceSignature(
        id="react-vite",
        match_files=["package.json", "vite.config.js"],
        roles=["frontend"],
        language="node",
        port_hint=5173,
    ),
    ServiceSignature(
        id="react-vite-ts",
        match_files=["package.json", "vite.config.ts"],
        roles=["frontend"],
        language="node",
        port_hint=5173,
    ),
    ServiceSignature(
        id="vue",
        match_files=["package.json", "vue.config.js"],
        roles=["frontend"],
        language="node",
        port_hint=8080,
    ),
    ServiceSignature(
        id="express",
        match_files=["package.json"],
        match_contains={"package.json": "express"},
        roles=["backend"],
        language="node",
        port_hint=3000,
    ),
    ServiceSignature(
        id="fastify",
        match_files=["package.json"],
        match_contains={"package.json": "fastify"},
        roles=["backend"],
        language="node",
        port_hint=3000,
    ),
    ServiceSignature(
        id="node-generic",
        match_files=["package.json"],
        roles=["backend"],
        language="node",
        port_hint=3000,
    ),
    # Python
    ServiceSignature(
        id="django",
        match_files=["manage.py"],
        roles=["backend", "frontend"],
        language="python",
        port_hint=8000,
    ),
    ServiceSignature(
        id="fastapi",
        match_files=["requirements.txt"],
        match_contains={"requirements.txt": "fastapi"},
        roles=["backend"],
        language="python",
        port_hint=8000,
    ),
    ServiceSignature(
        id="fastapi-pyproject",
        match_files=["pyproject.toml"],
        match_contains={"pyproject.toml": "fastapi"},
        roles=["backend"],
        language="python",
        port_hint=8000,
    ),
    ServiceSignature(
        id="flask",
        match_files=["requirements.txt"],
        match_contains={"requirements.txt": "flask"},
        roles=["backend", "frontend"],
        language="python",
        port_hint=5000,
    ),
    ServiceSignature(
        id="python-generic",
        match_files=["requirements.txt"],
        roles=["backend"],
        language="python",
        port_hint=5000,
    ),
    ServiceSignature(
        id="python-generic-toml",
        match_files=["pyproject.toml"],
        roles=["backend"],
        language="python",
        port_hint=5000,
    ),
    # Java
    ServiceSignature(
        id="spring-boot",
        match_files=["pom.xml"],
        match_contains={"pom.xml": "spring-boot"},
        roles=["backend"],
        language="java",
        port_hint=8080,
    ),
    ServiceSignature(
        id="spring-boot-gradle",
        match_files=["build.gradle"],
        match_contains={"build.gradle": "spring-boot"},
        roles=["backend"],
        language="java",
        port_hint=8080,
    ),
    ServiceSignature(
        id="java-generic-maven",
        match_files=["pom.xml"],
        roles=["backend"],
        language="java",
        port_hint=8080,
    ),
    ServiceSignature(
        id="java-generic-gradle",
        match_files=["build.gradle"],
        roles=["backend"],
        language="java",
        port_hint=8080,
    ),
    # Ruby
    ServiceSignature(
        id="rails",
        match_files=["Gemfile"],
        match_contains={"Gemfile": "rails"},
        roles=["backend", "frontend"],
        language="ruby",
        port_hint=3000,
    ),
    ServiceSignature(
        id="ruby-generic",
        match_files=["Gemfile"],
        roles=["backend"],
        language="ruby",
        port_hint=3000,
    ),
    # PHP
    ServiceSignature(
        id="laravel",
        match_files=["composer.json", "artisan"],
        roles=["backend", "frontend"],
        language="php",
        port_hint=8000,
    ),
    ServiceSignature(
        id="php-generic",
        match_files=["composer.json"],
        roles=["backend"],
        language="php",
        port_hint=8000,
    ),
    # Go
    ServiceSignature(
        id="go-generic",
        match_files=["go.mod"],
        roles=["backend"],
        language="go",
        port_hint=8080,
    ),
    # gRPC
    ServiceSignature(
        id="grpc-bare",
        match_files=[], # Custom logic for *.proto
        roles=["rpc"],
        language="unknown",
        port_hint=50051,
        protocol="grpc",
    ),
    # Static
    ServiceSignature(
        id="static-html",
        match_files=["index.html"],
        roles=["frontend"],
        language="static",
        port_hint=80,
    )
]

def _check_contains(filepath: str, pattern: str) -> bool:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
            return pattern.lower() in content
    except Exception:
        return False

def _match_signature(dirpath: str, files_in_dir: List[str]) -> Optional[ServiceSignature]:
    # Custom proto check for bare grpc
    has_proto = any(f.endswith(".proto") for f in files_in_dir)
    
    for sig in SIGNATURES:
        # Check bare grpc
        if sig.id == "grpc-bare":
            # Only match if there are protos and no other major manifest (like package.json, go.mod, etc.)
            if has_proto and not any(m in files_in_dir for m in ["package.json", "go.mod", "pom.xml", "requirements.txt", "pyproject.toml"]):
                return sig
            continue
            
        # Check files match
        if not all(mf in files_in_dir for mf in sig.match_files):
            continue
            
        # Check contains
        contains_match = True
        for mf, pattern in sig.match_contains.items():
            if not _check_contains(os.path.join(dirpath, mf), pattern):
                contains_match = False
                break
                
        if contains_match:
            return sig
            
    # Fallback to unknown if a manifest is found but no specific signature matches
    manifests = ["package.json", "requirements.txt", "pyproject.toml", "manage.py", "pom.xml", "build.gradle", "Gemfile", "composer.json", "go.mod"]
    if any(m in files_in_dir for m in manifests):
        # Determine language based on manifest
        lang = "unknown"
        if "package.json" in files_in_dir: lang = "node"
        elif "requirements.txt" in files_in_dir or "pyproject.toml" in files_in_dir or "manage.py" in files_in_dir: lang = "python"
        elif "pom.xml" in files_in_dir or "build.gradle" in files_in_dir: lang = "java"
        elif "Gemfile" in files_in_dir: lang = "ruby"
        elif "composer.json" in files_in_dir: lang = "php"
        elif "go.mod" in files_in_dir: lang = "go"
        
        return ServiceSignature(
            id="unknown",
            match_files=[],
            roles=["backend"], # Default guess
            language=lang,
            port_hint=8080
        )
        
    return None

def detect_datastores(source_dir: str) -> List[Dict[str, Any]]:
    datastores = []
    
    # Check docker-compose files
    for filename in os.listdir(source_dir):
        if filename.startswith("docker-compose") and filename.endswith((".yml", ".yaml")):
            filepath = os.path.join(source_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    compose = yaml.safe_load(f)
                    
                if compose and "services" in compose:
                    for srv_name, srv_def in compose["services"].items():
                        image = srv_def.get("image", "").lower()
                        if any(db in image for db in ["postgres", "mysql", "mongo", "redis", "kafka", "rabbitmq", "mariadb", "elasticsearch"]):
                            datastores.append({
                                "name": srv_name,
                                "role": ["datastore"],
                                "attacked": False,
                                "image": image
                            })
            except Exception:
                pass
                
    return datastores

def detect_services(source_dir: str) -> Dict[str, Any]:
    services_dict = {}
    claimed_roots = []
    
    for root, dirs, files in os.walk(source_dir):
        # Skip hidden dirs and common non-source dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {"node_modules", "vendor", "__pycache__", "dist", "build", "venv", ".venv"}]
        
        # Check if current root is under any claimed root
        is_subfolder = any(root.startswith(os.path.join(claimed, "")) or root == claimed for claimed in claimed_roots)
        if is_subfolder:
            continue
            
        sig = _match_signature(root, files)
        if sig:
            rel_path = os.path.relpath(root, source_dir)
            if rel_path == ".":
                name = os.path.basename(os.path.abspath(source_dir)) or "app"
            else:
                name = rel_path.replace(os.sep, "-")
                
            confidence = "high" if sig.id != "unknown" else "low"
            
            services_dict[name] = {
                "name": name,
                "path": rel_path,
                "stack": sig.id,
                "role": sig.roles,
                "language": sig.language,
                "protocol": sig.protocol,
                "port_hint": sig.port_hint,
                "confidence": confidence,
                "agents_override": sig.agents
            }
            claimed_roots.append(root)

    # Resolve port collisions
    used_ports = set()
    for srv in services_dict.values():
        port = srv["port_hint"]
        while port in used_ports:
            port += 1
        srv["port"] = port
        used_ports.add(port)
        
    datastores = detect_datastores(source_dir)
    
    result = {
        "services": services_dict,
        "datastores": datastores
    }
    
    # Write to .cyphex/services.json
    cyphex_dir = os.path.join(source_dir, ".cyphex")
    os.makedirs(cyphex_dir, exist_ok=True)
    with open(os.path.join(cyphex_dir, "services.json"), "w") as f:
        json.dump(result, f, indent=2)
        
    return result
