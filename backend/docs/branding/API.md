# White Label & Custom Branding API Specifications

All routes are prefixed with `/api/v1`.

## Branding Customization

### GET `/branding/resolve`
Fetch cascading effective styling attributes for a client at a specific location.
- **Parameters**: `organization_id`, `location_id` (optional)
- **Response**:
  ```json
  {
    "id": "uuid",
    "company_name": "Target Shop",
    "primary_color": "#4F46E5",
    "theme": "light"
  }
  ```

### PUT `/branding/organization/{organization_id}`
Updates company names, support channels, and palette colors.

## Captive Portal Themes

### GET `/themes/branding/{branding_id}`
Fetch landing themes, terms, banners, and custom scripts.

### PUT `/themes/branding/{branding_id}`
Modifies custom JavaScript, custom CSS, advertisement images, and legal texts.

## Custom Hostnames

### POST `/domains`
Add a custom mapping hostname.
- **Payload**:
  ```json
  {
    "organization_id": "uuid",
    "domain_name": "portal.mybrand.com"
  }
  ```

### POST `/domains/{domain_id}/verify`
Validate DNS TXT records to activate the custom domain mapping.
