from __future__ import annotations

import sys

from cli import build_parser, run_cli


def main() -> int:
    parser = build_parser()
    args, _ = parser.parse_known_args()
    if args.gui or not args.cli:
        from gui.app import run_app

        return run_app(sys.argv)
    return run_cli(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
