"""
nemo-tollwarden — TollWarden payment security for the NVIDIA NeMo Agent Toolkit.

Registers three NeMo functions (tollwarden_scan_payment, tollwarden_check_reputation,
tollwarden_report_counterparty) via the `nat.components` entry point. Importing this
package runs the registrations in `register.py`.

To make a block stop the payment rather than relying on the model to obey the
verdict, wrap the workflow's payment executor (sync or async):

    from nemo_tollwarden import guarded_payment

    safe_pay = guarded_payment(execute_x402_payment, client)
    await safe_pay(payment, content=page_text)  # raises TollWardenBlockedError on block

TollWarden is advisory and non-custodial — it never touches keys, wallets, or funds.
"""
from __future__ import annotations

__version__ = "0.1.0"

# Importing the register module runs the @register_function decorators. The
# nat.components entry point in pyproject.toml points here so the toolkit loads
# these functions on initialization.
from . import register  # noqa: F401,E402
from .guard import guarded_payment  # noqa: E402

__all__ = ["guarded_payment", "register", "__version__"]
