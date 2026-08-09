import sys
import os
sys.path.insert(0, '.')
sys.path.insert(1, '..')
import asyncio
from deepagents.oracle_attack import AttackOracle

async def test():
    o = AttackOracle()
    r = await o.plan('http://localhost:3000', 'surface summary', 'Business Logic')
    print("RESULT:", r)

asyncio.run(test())
