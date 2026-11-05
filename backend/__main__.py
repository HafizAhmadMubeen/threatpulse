"""Run the API: python -m backend

The host is fixed on purpose. The API has no login, so it must stay on loopback.
"""

import uvicorn

from backend.app import HOST, PORT, app_from_environment


def main() -> None:
    uvicorn.run(app_from_environment(), host=HOST, port=PORT)


if __name__ == "__main__":
    main()
