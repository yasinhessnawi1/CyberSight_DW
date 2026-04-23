#!/usr/bin/env python3
"""
Download the CICIDS 2017 dataset (full columns version with Source IP, Timestamp, Label).
Source: vishwa132/CICIDS-2017 on Hugging Face (originally bvk/CICIDS-2017).

This version includes: Src IP dec, Dst IP dec, Src Port, Dst Port, Protocol,
Timestamp, 80+ flow features, Label, Attempted Category.
"""

import os
import sys
import urllib.request
import argparse
import subprocess

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'cicids2017')

HF_BASE = "https://huggingface.co/datasets/vishwa132/CICIDS-2017/resolve/main/"

FILES = {
    "monday.csv":    146_000_000,
    "tuesday.csv":   125_000_000,
    "wednesday.csv": 207_000_000,
    "thursday.csv":  133_000_000,
    "friday.csv":    200_000_000,
}

EXPECTED_FINAL = list(FILES.keys())

DEFAULT_VOLUME_NAME = "cybersightdw_etl_data"


def download(url: str, dest: str, expected_size: int) -> bool:
    if os.path.exists(dest):
        actual = os.path.getsize(dest)
        if actual > expected_size * 0.8:
            print(f"  SKIP {os.path.basename(dest)} (already downloaded, {actual / 1048576:.1f} MB)")
            return True
        else:
            print(f"  RE-DOWNLOAD {os.path.basename(dest)} (incomplete: {actual / 1048576:.1f} MB)")

    print(f"  Downloading {os.path.basename(dest)} ...")
    try:
        urllib.request.urlretrieve(url, dest, reporthook=_progress)
        print()
        actual = os.path.getsize(dest)
        print(f"    Done: {actual / 1048576:.1f} MB")
        return True
    except Exception as e:
        print(f"\n    FAILED: {e}")
        return False


def _progress(block_num, block_size, total_size):
    downloaded = block_num * block_size
    if total_size > 0:
        pct = min(100, downloaded * 100 / total_size)
        mb = downloaded / 1048576
        total_mb = total_size / 1048576
        print(f"\r    {pct:5.1f}%  {mb:.1f}/{total_mb:.1f} MB", end='', flush=True)
    else:
        mb = downloaded / 1048576
        print(f"\r    {mb:.1f} MB downloaded", end='', flush=True)


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def _docker_volume_exists(volume_name: str) -> bool:
    try:
        subprocess.run(
            ["docker", "volume", "inspect", volume_name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def _ensure_docker_volume(volume_name: str) -> None:
    if _docker_volume_exists(volume_name):
        return
    print(f"\nCreating Docker volume: {volume_name}")
    _run(["docker", "volume", "create", volume_name])


def _copy_into_volume(volume_name: str, source_dir: str) -> None:
    abs_src = os.path.abspath(source_dir)
    if not os.path.isdir(abs_src):
        raise FileNotFoundError(f"Source directory not found: {abs_src}")

    print(f"Copying CSV files into Docker volume '{volume_name}' ...")
    _run([
        "docker", "run", "--rm",
        "-v", f"{volume_name}:/data",
        "-v", f"{abs_src}:/src",
        "alpine",
        "sh", "-c", "mkdir -p /data/cicids2017 && cp /src/*.csv /data/cicids2017/",
    ])


def main():
    parser = argparse.ArgumentParser(description="Download CICIDS 2017 CSVs (Hugging Face mirror).")
    parser.add_argument(
        "--docker-volume",
        action="store_true",
        help=f"Create/populate external Docker volume (default name: {DEFAULT_VOLUME_NAME})",
    )
    parser.add_argument(
        "--volume-name",
        default=DEFAULT_VOLUME_NAME,
        help="External Docker volume name to populate (used with --docker-volume).",
    )
    args = parser.parse_args()

    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"Data directory: {DATA_DIR}")
    print(f"Source: Hugging Face (vishwa132/CICIDS-2017)\n")
    print("This version includes full columns: Source/Dest IP, Timestamp, Protocol, Label\n")

    print("Step 1: Downloading CSV files ...")
    failed = []
    for fname, expected_size in FILES.items():
        url = HF_BASE + fname
        dest = os.path.join(DATA_DIR, fname)
        if not download(url, dest, expected_size):
            failed.append(fname)

    if failed:
        print(f"\nFailed to download {len(failed)} file(s): {failed}")
        print("Check your internet connection and re-run the script.")
        sys.exit(1)

    print("\nVerification:")
    all_ok = True
    for fname in EXPECTED_FINAL:
        path = os.path.join(DATA_DIR, fname)
        if os.path.exists(path):
            size_mb = os.path.getsize(path) / (1024 * 1024)
            print(f"  OK   {fname} ({size_mb:.1f} MB)")
        else:
            print(f"  MISS {fname}")
            all_ok = False

    if all_ok:
        if args.docker_volume:
            try:
                _ensure_docker_volume(args.volume_name)
                _copy_into_volume(args.volume_name, DATA_DIR)
                print(f"\nDocker volume populated: {args.volume_name}")
            except FileNotFoundError as e:
                print(f"\nVolume copy failed: {e}")
                sys.exit(1)
            except subprocess.CalledProcessError as e:
                print(f"\nDocker command failed: {e}")
                print("Make sure Docker Desktop is running and the `docker` CLI is available.")
                sys.exit(1)

        print("\nAll files ready. You can now run: docker compose up --build")
    else:
        print("\nSome files are missing — check errors above.")
        sys.exit(1)


if __name__ == '__main__':
    main()
