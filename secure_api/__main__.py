import argparse
import os

from . import create_app, initialize_database


def main():
    parser = argparse.ArgumentParser(description="Information Security Lab 1 notes API")
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init-db")
    initialize.add_argument("--login", default="cheng")
    initialize.add_argument("--password-env", default="LAB_DEMO_PASSWORD")
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()
    if args.command == "init-db":
        password = os.environ.get(args.password_env)
        if password is None:
            parser.error(f"Set the {args.password_env} environment variable.")
        initialize_database(os.environ.get("LAB_DATABASE", "instance/lab1.sqlite3"),
                            args.login, password)
        print(f"Created account {args.login}; password stored as a bcrypt hash.")
    else:
        create_app().run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
