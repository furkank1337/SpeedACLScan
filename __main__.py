"""Entry point: `python -m speedaclscan` boots the local web server."""
import argparse

from .server import serve


def main():
    ap = argparse.ArgumentParser(prog="speedaclscan",
                                 description="AD attack-path analysis with masked AI assistance")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8777)
    args = ap.parse_args()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
