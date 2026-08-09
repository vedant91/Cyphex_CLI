import os
import asyncio
import logging

os.environ["TELEMETRY_DISABLED"] = "1"
os.environ["ENABLE_BACKEND_ACCESS_CONTROL"] = "false"
os.environ["CACHING"] = "false"

os.environ["LLM_PROVIDER"] = "ollama"
os.environ["LLM_MODEL"] = "ollama/llama3.1"
os.environ["LLM_ENDPOINT"] = "http://localhost:11434"
os.environ["LLM_API_KEY"] = "ollama"

os.environ["EMBEDDING_PROVIDER"] = "ollama"
os.environ["EMBEDDING_MODEL"] = "ollama/nomic-embed-text"
os.environ["EMBEDDING_ENDPOINT"] = "http://localhost:11434"
os.environ["EMBEDDING_API_KEY"] = "ollama"
os.environ["EMBEDDING_DIMENSIONS"] = "768"
os.environ["COGNEE_SKIP_CONNECTION_TEST"] = "true"

import cognee

async def main():
    await cognee.prune.prune_data()
    await cognee.add("Hello world this is a test", dataset_name="test_dataset")
    await cognee.cognify()
    print("Cognify successful!")

if __name__ == "__main__":
    asyncio.run(main())
