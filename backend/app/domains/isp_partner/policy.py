"""ISP parity policy switches (ADDENDUM_04 §7, founder questions F1-F4).

The founder has not answered F1-F4. Each default below is ADDENDUM_04's, and
each is ONE environment variable to flip -- no code change, no migration:

=====  ===================================  =========  ==========================
Q      Variable                             Default    Effect when flipped
=====  ===================================  =========  ==========================
F1     ISP_PARTNER_ADDON_DEFAULT_ALLOWANCE  ``none``   ``all``: an ISP with no
                                                       allowance rows may enable
                                                       every add-on (no cap).
F2     ISP_PARTNER_PII_UNMASKED             false      true: twins stop forcing
                                                       masking / redacting.
F3     ISP_PARTNER_BYO_SENDER_SCOPE         ``isp``    ``customer``: each
                                                       customer brings its own
                                                       messaging sender.
F4     ISP_PARTNER_WHITE_LABEL              ``plan``   ``off``: no white-label
                                                       twin for ISPs at all.
=====  ===================================  =========  ==========================

F4 ``plan`` means: the portal branding twins exist, and the customer's own plan
decides (``RequireFeature(WHITE_LABEL)`` re-applied by ``twin_gates``). The
partner console itself stays Wyfy-branded either way.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["IspPartnerPolicy", "get_isp_partner_policy"]


class IspPartnerPolicy(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ISP_PARTNER_",
        case_sensitive=False,
        extra="ignore",
    )

    addon_default_allowance: Literal["none", "all"] = Field(default="none")
    pii_unmasked: bool = Field(default=False)
    byo_sender_scope: Literal["isp", "customer"] = Field(default="isp")
    white_label: Literal["plan", "off"] = Field(default="plan")


@lru_cache(maxsize=1)
def get_isp_partner_policy() -> IspPartnerPolicy:
    return IspPartnerPolicy()
