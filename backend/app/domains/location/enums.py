"""Enumerations for the Location domain.

Stored as plain ``String`` columns on the ORM model (mirroring
``app.domains.organization.enums``'s documented convention -- e.g.
``Organization.status`` -- rather than native PostgreSQL enum types) so
adding a new value never requires an ``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum


class LocationStatus(StrEnum):
    """Lifecycle status of a location.

    Deliberately **not** a copy of ``OrganizationStatus`` (``trial`` /
    ``active`` / ``suspended`` / ``archived``) -- a location has no
    subscription/trial concept of its own (billing lives entirely at the
    organization level, see ``docs/location/LOCATION_ARCHITECTURE.md``), so
    ``TRIAL`` would be meaningless here. Instead:

    * ``ACTIVE`` -- the site is live: guest WiFi/services are expected to be
      operating normally.
    * ``INACTIVE`` -- the location record exists (address, contact, timezone
      already on file) but is not currently operational -- e.g. a site being
      onboarded before its routers are provisioned, a seasonal location that
      is closed for part of the year, or a location temporarily taken
      offline for maintenance. This is the "not live yet / not live right
      now" state, distinct from an administrative suspension.
    * ``SUSPENDED`` -- administratively disabled, independent of the rest of
      the organization's status. An organization can remain ``ACTIVE`` while
      one specific location is ``SUSPENDED`` (e.g. a compliance incident, a
      safety issue, or a billing dispute scoped to that single site) --
      this is the meaningful difference from organization-level suspension,
      which takes down the entire tenant. Only an explicit
      ``activate``/``suspend`` action transitions a location into or out of
      this state (mirrors ``OrganizationStatus.SUSPENDED``'s semantics,
      narrowed to a single site).
    * ``ARCHIVED`` -- soft-deleted (via ``BaseModel``'s soft-delete mixin);
      the location is no longer in service permanently (e.g. the site
      closed for good). Never assigned automatically -- only via
      ``LocationService.archive_location``.
    """

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class PropertyType(StrEnum):
    """The kind of physical property a :class:`~.models.Location` is --
    purely descriptive/reporting metadata (drives no branching business
    logic anywhere in this domain today), added for Smart Location
    Provisioning's "Create Location" form (see ``docs/location/FLOW.md``).

    Nullable on the model (``Location.property_type``) -- every ``Location``
    row created before this addition has none, and a caller creating a
    location through the plain ``POST /organizations/{id}/locations``
    endpoint may still reasonably omit it (mirrors ``latitude``/
    ``longitude``'s own "known but not always provided up front" nullability
    reasoning already documented on the model).
    """

    HOTEL = "hotel"
    RESORT = "resort"
    CAFE = "cafe"
    RESTAURANT = "restaurant"
    HOSPITAL = "hospital"
    CLINIC = "clinic"
    OFFICE = "office"
    COWORKING_SPACE = "coworking_space"
    SCHOOL = "school"
    COLLEGE = "college"
    UNIVERSITY = "university"
    MALL = "mall"
    AIRPORT = "airport"
    FACTORY = "factory"
    WAREHOUSE = "warehouse"
    APARTMENT = "apartment"
    HOSTEL = "hostel"
    CUSTOM = "custom"
