# White Label Customization Lifecycle Flows

## 1. Cascading Visual Resolver Flow
```
                     [Client connects at Location X]
                                    |
                                    v
                     Does Location-specific Branding exist?
                       /                       \
                     (Yes)                     (No)
                     /                           \
        [Return Location Branding]       [Return parent Org Branding]
```

## 2. Custom Domain DNS Verification Flow
```
[User App] ---> (POST /domains) ---> [Generate verification token]
                                             |
                                             v
[Web UI] <--- [Show challenge string: cloudguest-verification=hex...]
   |
   v (User adds TXT record on domain registrar)
[User App] ---> (POST /verify) ---> [Perform DNS TXT Query check]
                                             |
                         -----------------------------------------
                        |                                         |
                     (Valid)                                  (Invalid)
                        |                                         |
                        v                                         v
            [Mark is_verified=True]                       [Return Error]
            [Start SSL Certificate Request]
```
