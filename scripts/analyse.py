"""Offline CLI using the same bounded worker as the API."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"backend"))
from jobs import execute
from settings import AnalysisError, MAX_UPLOAD

def main():
    parser=argparse.ArgumentParser(description="Analyse a local firmware file; emit masked JSON.")
    parser.add_argument("file",type=Path);parser.add_argument("--expected-sha256",default="")
    parser.add_argument("--binwalk",action="store_true");parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    try:
        if not 0 < args.file.stat().st_size <= MAX_UPLOAD: raise AnalysisError("Input must be between 1 byte and 64 MiB.")
        result=execute(args.file.read_bytes(),{"filename":args.file.name,"expected_sha256":args.expected_sha256,"use_binwalk":args.binwalk})
        output=json.dumps(result,indent=2)
        if args.output: args.output.write_text(output+"\n",encoding="utf-8")
        else: print(output)
    except (AnalysisError,OSError) as error:
        print(error.message if isinstance(error,AnalysisError) else "Could not read input or write output.",file=sys.stderr);return 1
    return 0

if __name__ == "__main__": sys.exit(main())
