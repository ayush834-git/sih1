"""One-command Day-1 check: synthetic pipeline followed by offline unit tests."""
import subprocess, sys
from scenarios.smoke_pipeline import run

if __name__ == "__main__":
    run()
    raise SystemExit(subprocess.call([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]))
