"""Command line: ``python3 -m app serve``."""

import argparse
import os
import signal
import sys

from . import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -m app", description="portnook (home gateway)")
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="run the web UI/API and the agent loops")
    serve.add_argument("--listen", default=os.environ.get("PF_LISTEN", "0.0.0.0"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("PF_PORT", "8090")))
    serve.add_argument("--data", default=os.environ.get("PF_DATA", "/data"))
    serve.add_argument("--web", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web"))
    serve.add_argument("--wg-dir", default="/etc/wireguard")
    sub.add_parser("version", help="print the version")
    args = parser.parse_args(argv)

    if args.command == "version":
        print(__version__)
        return 0
    if args.command != "serve":
        parser.print_help()
        return 2

    from .agent import Agent
    from .api import Server
    from .log import log
    from .net import Net
    from .store import Store

    os.umask(0o077)
    store = Store(os.path.join(args.data, "agent.json"))
    agent = Agent(store, Net(wg_dir=args.wg_dir), version=__version__)
    server = Server((args.listen, args.port), agent, args.web)

    def stop(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    log("portnook %s listening on %s:%d", __version__, args.listen, args.port)
    agent.startup()
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        log("portnook stopping")
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
