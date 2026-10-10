"""Run the lab API on the loopback interface."""


def main() -> None:
    """Start uvicorn bound to localhost.

    Binding to ``127.0.0.1`` keeps the teaching server off other network
    interfaces. This process still has no TLS. Use it for coursework only.
    """

    import uvicorn

    uvicorn.run(
        "secure_notes.app:create_app",
        factory=True,
        host="127.0.0.1",
        port=8000,
    )


if __name__ == "__main__":
    main()
