import httpx
import os
from dotenv import load_dotenv
import asyncio

load_dotenv()

NETBIRD_API_URL = os.getenv("NETBIRD_API_URL", "https://api.netbird.io/api")
NETBIRD_API_TOKEN = os.getenv("NETBIRD_API_TOKEN")

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": f"Token {NETBIRD_API_TOKEN}"
}

async def main():
    async with httpx.AsyncClient() as client:
        # Check Setup Keys
        resp = await client.get(f"{NETBIRD_API_URL}/setup-keys", headers=headers)
        if resp.status_code == 200:
            print(f"Setup Keys: {len(resp.json())} keys found.")
            for k in resp.json():
                print(f" - {k.get('name')}: {k.get('key')}")
        else:
            print(f"Error fetching setup keys: {resp.status_code} {resp.text}")

        # Check Policies
        resp = await client.get(f"{NETBIRD_API_URL}/policies", headers=headers)
        if resp.status_code == 200:
            print(f"Policies: {len(resp.json())} policies found.")
            for p in resp.json():
                print(f" - {p.get('name')}")
        else:
            print(f"Error fetching policies: {resp.status_code} {resp.text}")

if __name__ == "__main__":
    asyncio.run(main())
