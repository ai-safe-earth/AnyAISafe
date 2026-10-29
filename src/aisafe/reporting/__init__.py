"""src/aisafe/reporting/__init__.py
--------------------------------
The renderers of `aisafe audit`: `report` (json, sarif, markdown, terminal, dispatch) and
`html` (the standalone page). Import the modules; nothing is re-exported here, so the lazy
import order between the two stays explicit.
"""

from __future__ import annotations
