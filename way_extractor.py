#!/usr/bin/env python3
import re
import os
import sys
import argparse

# Built-in default extensions to filter URLs from os doc
DEFAULT_EXTENSIONS = {
    "pem","env","sql","cfg","config","apk","json","yml","yaml","xml","log",
    "git","enc","key","ini","ps1","sh","bat","exe","cgi","msi","jar","py",
    "db","mdb","bak","bkp","bkf","inc","asa","old","iso","bin","swf","pl",
    "htm","txt","doc","docx","xls","xlsx","ppt","pptx","pdf","eml","email",
    "msg","gadget","tmp","temp","xz","dll","bz2","do","zst","bz","gz","ovpn",
    "vpn","rar","zip","zipx","tar","lzma","7z","7zip","deb","pkg","ipa","git"
}

# Regex patterns for secrets detection copied from doc
SECRET_REGEXES = [
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z-_]{35}",
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    r"-----BEGIN (RSA|EC|DSA|PGP) PRIVATE KEY-----",
    r"xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}",
    r"ghp_[A-Za-z0-9]{36}",
    r"sk_live_[0-9a-zA-Z]{24}",
    r"key-[0-9a-zA-Z]{32}",
    r"SK[0-9a-fA-F]{32}",
    r"https:\/\/[a-z0-9-]+\.firebaseio\.com",
    r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    r"EAACEdEose0cBA[0-9A-Za-z]+",
    r"sl\.[A-Za-z0-9\-\_]{140}",
    r"dop_v1_[A-Za-z0-9]{64}",
    r"SHA256:[A-Za-z0-9+/=]{43}",
    r"[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@",
    r"mysql:\/\/[A-Za-z0-9._%+-]+:[^@]+@[A-Za-z0-9.-]+:[0-9]+\/[A-Za-z0-9_]+",
    r"postgres(?:ql)?:\/\/[A-Za-z0-9._%+-]+:[^@]+@[A-Za-z0-9.-]+:[0-9]+\/[A-Za-z0-9_]+",
    r"mongodb(?:\+srv)?:\/\/[A-Za-z0-9._%+-]+:[^@]+@[A-Za-z0-9.-]+\/[A-Za-z0-9_]+",
    r"amzn\.mws\.[A-Za-z0-9]{8,}",
    r"cloudinary:\/\/[0-9]{15}:[A-Za-z0-9_-]+@[A-Za-z0-9-]+",
]

# URL regex to catch anything looking like a URL
URL_REGEX = re.compile(
    r"https?://[^\s'\"<>]+"
)

def load_file_list(file_path):
    try:
        with open(file_path, "r") as f:
            files = [line.strip() for line in f if line.strip()]
        return files
    except Exception as e:
        print(f"[ERROR] Failed loading file list from {file_path}: {e}", file=sys.stderr)
        sys.exit(1)

def scan_file(file_path, secrets, raw_urls, filtered_urls, ext_filter_include, ext_filter_exclude):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Extract all URLs (raw)
                urls = URL_REGEX.findall(line)
                for url in urls:
                    raw_urls.add(url)
                    if url_has_allowed_extension(url, ext_filter_include, ext_filter_exclude):
                        filtered_urls.add(url)

                # Extract secrets with regex
                for regex in SECRET_REGEXES:
                    matches = re.findall(regex, line)
                    for match in matches:
                        # Save secrets with file and line info
                        secrets.append(f"{file_path}:{line_num}: {match}")

    except Exception as e:
        print(f"[WARN] Skipping file {file_path} due to read error: {e}", file=sys.stderr)

def url_has_allowed_extension(url, include_set, exclude_set):
    # Strip query params to check extension only
    url_path = url.split("?", 1)[0]
    ext = os.path.splitext(url_path)[1].lower().strip(".")
    if include_set and ext not in include_set:
        return False
    if exclude_set and ext in exclude_set:
        return False
    return True

def gather_files(paths):
    """Expand directories, collect all files"""
    all_files = []
    for path in paths:
        if os.path.isfile(path):
            all_files.append(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    all_files.append(os.path.join(root, file))
        else:
            print(f"[WARN] Skipping invalid path: {path}", file=sys.stderr)
    return all_files

def main():
    parser = argparse.ArgumentParser(
        description="WAY_EXTRACTOR: Brutal secret & URL hunter with extension filtering & filelist input"
    )
    parser.add_argument(
        "-i", "--include",
        help=f"Comma-separated list of file extensions to INCLUDE for URL filtering (default built-in list)",
        default=",".join(DEFAULT_EXTENSIONS)
    )
    parser.add_argument(
        "-x", "--exclude",
        help="Comma-separated list of file extensions to EXCLUDE from URL filtering",
        default=""
    )
    parser.add_argument(
        "-l", "--filelist",
        help="File containing list of file paths to scan, one per line",
        default=None
    )
    parser.add_argument(
        "-f", "--files",
        nargs="*",
        help="Files or directories to scan (default: current directory)",
        default=["."]
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help=" print only final categorized results"
    )

    args = parser.parse_args()

    # Parse extension include/exclude sets
    ext_filter_include = set(ext.strip().lower() for ext in args.include.split(",") if ext.strip())
    ext_filter_exclude = set(ext.strip().lower() for ext in args.exclude.split(",") if ext.strip())

    # Load files from filelist if provided, else from args.files
    if args.filelist:
        files = load_file_list(args.filelist)
    else:
        files = gather_files(args.files)

    if not files:
        print("[ERROR] No files found to scan.", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"[INFO] Scanning {len(files)} files...")

    secrets = []
    raw_urls = set()
    filtered_urls = set()

    for file_path in files:
        scan_file(file_path, secrets, raw_urls, filtered_urls, ext_filter_include, ext_filter_exclude)

    # Output categorized results
    print("\n==== RAW URLs (ALL) ====")
    for url in sorted(raw_urls):
        print(url)

    print("\n==== FILTERED URLs (with included extensions) ====")
    for url in sorted(filtered_urls):
        print(url)

    print("\n==== SECRETS FOUND ====")
    for secret in secrets:
        print(secret)

if __name__ == "__main__":
    main()

