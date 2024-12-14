from argparse import ArgumentParser, FileType

from util import insert_c_file, get_version


def main() -> int:
    ap = ArgumentParser()
    ap.add_argument("source", type=FileType("r+"), help="source file")
    args = ap.parse_args()
    version = get_version()
    version_str = f"{version["major"]}.{version["minor"]}.{version["patch"]}"
    if len(version["extra"]):
        version_str += "-" + version["extra"]
    insert_c_file(
        args.source,
        [f'static const char* const bbre_version_str = "{version_str}";\n'],
        "",
        file_name="versioner.py",
    )
    args.source.close()
    return 0


if __name__ == "__main__":
    main()
