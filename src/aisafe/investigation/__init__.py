"""src/aisafe/investigation/__init__.py
-------------------------------------
The investigation half of the workbench: the plan of surfaces to read (`plan`), the record
format through which an investigator's reasoning enters aisafe (`records`), and the
mechanical validation of those records against the audited tree (`validate`). Nothing in
this package calls a model or opens a socket; the reasoning happens in the host coding
agent and arrives only as attributed records.
"""

from __future__ import annotations
