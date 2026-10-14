"""Launch the Public Sector Agent Delegated Authority Demo UI.

    python demo/public_sector_hallpass/app.py              # http://127.0.0.1:8765
    python demo/public_sector_hallpass/app.py --port 9000

The server code lives in hallpass_ui.py (named so it cannot shadow the CDK
app.py at the project root when tests import it).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hallpass_ui import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
