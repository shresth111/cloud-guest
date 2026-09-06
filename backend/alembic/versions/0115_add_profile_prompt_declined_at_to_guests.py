"""Two nullable timestamps on ``guests``: ``profile_prompt_declined_at``
and ``review_link_opened_at``.

Both exist for the same reason and are added together because separating
them would only make the second look optional: each is a piece of
"has this guest already answered this card" state that the portal used to
keep -- or would otherwise have kept -- in the guest's browser.

## What it is for

It is the third input to ``GuestLoginResponse.has_profile`` -- the new bit
that tells the portal whether to render the post-connect "add your name"
card at all. The other two inputs are columns that already exist
(``display_name``, ``email``). This one records the answer a guest gives
when the answer is *no*.

## Why the server has to hold it

The portal remembers a decline in ``localStorage`` today. Web Storage
**throws inside Apple's Captive Network Assistant**. The read is
try/catch-wrapped, so it does not crash -- this codebase already learned
that lesson the expensive way, and ``scripts/test-portal-cna-storage-
safety.mjs`` exists to keep it learned -- but a read that always throws
always returns "not answered".

The consequence in the field: an iPhone guest connects for the first time,
types their name, taps Save, and the NAS bounces them back to
``/portal/session`` as a brand-new document, which is routine. The storage
read throws. They are asked for their name again, having just given it. On
the platform where the browser is worst, the product nagged hardest.

A column survives storage loss, survives the websheet, and follows the
guest across devices -- none of which device-local state could ever do.

## Nullable, and no backfill

NULL means "has not declined", which is the truth for every existing row:
nobody has ever been able to tell this platform they were declining, so
nobody has. There is no history to reconstruct and none is invented. The
device-local flags that exist in guests' browsers today are unreadable from
here and are simply lost -- the cost is that a guest who dismissed the card
on a device whose storage still works may be asked once more, once, and
then never again.

A timestamp rather than a boolean because "when" is the question anyone
asks next -- of a frequency rule, a support ticket, or a DPDP records
request -- and a boolean cannot be widened into one afterwards.

## ``review_link_opened_at``

The same shape for the review card. Non-null is
``GuestLoginResponse.has_opened_review_link``; the portal reads that bit
and stops re-rendering the card to a guest who has already tapped
through. Without it there is no server-side record at all and the card
re-appears on every visit forever -- which is the difference between a
feature and a nag, and it lands hardest on the guest who actually did
what was asked.

⚠ **It records an opened link, not a written review, and it cannot see
iOS.** Google exposes nothing that would let this platform know whether a
review was left. And iPhone/iPad guests are sent to
``captive.apple.com/hotspot-detect.html`` after login rather than to
``/portal/session`` -- deliberately: the Captive Network Assistant
releases app traffic only when its probe to that exact URL returns
Apple's success body, and landing the CNA back in the SPA is a confirmed
cause of devices authenticating on the NAS while every connection stayed
pinned to the portal host. So iOS guests never reach the screen this card
is on and never write this column. Any count over it is a count of
Android and desktop guests who tapped a link. Reported as anything else
it is a lie, and a dashboard will repeat it.

Unlike ``profile_prompt_declined_at``, this one is overwritten on each
open rather than kept as a first touch: a decline is an answer given
once, and "when did they last go and review us" is a question whose
useful answer is the most recent one.

Revision ID: 0115_add_profile_prompt_declined_at_to_guests
Revises: 0114_add_post_connect_ask_columns_to_captive_portal_configs
Create Date: 2026-09-06
"""

import sqlalchemy as sa

from alembic import op

revision = "0115_add_profile_prompt_declined_at_to_guests"
down_revision = "0114_add_post_connect_ask_columns_to_captive_portal_configs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guests",
        sa.Column(
            "profile_prompt_declined_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "guests",
        sa.Column(
            "review_link_opened_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("guests", "review_link_opened_at")
    op.drop_column("guests", "profile_prompt_declined_at")
