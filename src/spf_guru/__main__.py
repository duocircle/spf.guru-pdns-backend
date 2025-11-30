"""Entry point for running the application directly."""

import uvicorn


def main():
    """Run the application."""
    uvicorn.run(
        "spf_guru.app:app",
        host="0.0.0.0",
        port=8000,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
