# =============================================================
#  WYFY GUEST -- MIKROTIK ROUTER SETUP
#  RouterOS 7.x  |  banaya 21 Aug 2026
#
#  ISTEMAAL KAISE KARNA HAI
#  ------------------------
#  Ye poori file EK SAATH paste NAHI karni hai.
#  Ek STEP ka block copy karo -> WinBox New Terminal me paste karo
#  -> output padho -> tabhi agle STEP pe jao.
#
#  Har step apna PASS / FAIL khud print karta hai.
#  FAIL aaye to wahin ruk jao. Aage badh ke baad me theek karne
#  ki koshish mat karna -- neeche ka har step upar wale ke sahi
#  hone pe tika hai, aur zyadatar chup-chaap fail hote hain.
#
#  DO CHEEZEIN JO KABHI MAT KARNA
#  1. Master console me "Generate" dobara mat dabana. Ek router =
#     ek Generate. Dobara dabane se server pe 4 secrets badal jaate
#     hain, device pe purane reh jaate hain, aur router pe koi
#     error nahi aata.
#  2. Koi step skip mat karna kyunki "pichhla to clearly chal gaya".
#     RouterOS ka `set [find ...]` khaali match pe bhi success deta hai.
# =============================================================


# =============================================================
#  STEP 0  --  FACTORY RESET   (sirf naye router pe)
# =============================================================
#  Laptop cable se ether2 me, ISP ka cable ether1 me.
#  WinBox se MAC ADDRESS se connect karo, IP se nahi.
#
#  Agar router already aadha configure hai aur tum use continue
#  karna chahte ho, to ye step SKIP karo aur STEP 1 se shuru karo.
#
#  Neeche wali line chalane pe router reboot hoga (~2 min) aur
#  connection tootega. Ye normal hai. MAC se dobara connect karna.

/system reset-configuration skip-backup=yes

#  Reset ke baad ye chala ke dekho ki internet aa raha hai:
#
#  /interface print
#  /ping 8.8.8.8 count=4
#
#  ether1 ke flags me "R" hona chahiye, aur ping ke replies aane
#  chahiye. Ping fail = neeche kuch bhi kaam nahi karega. Pehle
#  cable / ISP / PPPoE theek karo.


# =============================================================
#  STEP 1  --  GHADI SET KARO
# =============================================================
#  hEX me battery clock nahi hoti, isliye har factory-fresh ya
#  power-cut wala box GALAT DATE pe boot hota hai. Generated
#  script me NTP ki ek bhi command nahi hai.
#
#  Galat clock pe kya hota hai: router aur guests theek chalenge,
#  par Master console pe router HAMESHA OFFLINE dikhega, kyunki
#  heartbeat scheduler galat date se start-time uthata hai.
#  Koi error kahin nahi aata.
#
#  IP address use kar rahe hain kyunki DNS abhi set nahi hua.
#  ---- YAHAN SE COPY KARO ----

/system clock set time-zone-name=Asia/Kolkata
/system ntp client set enabled=yes servers=216.239.35.0,162.159.200.1
:put "NTP set. 15 second ruko..."
:delay 15s
:put "===================================================="
:put ("  CLOCK  : " . [/system clock get date] . " " . [/system clock get time])
:if ([:typeof [:find [/system clock get date] "2026"]] = "nothing") do={ :put "  RESULT  : FAIL -- date galat hai. Ruk jao." } else={ :put "  RESULT  : PASS" }
:put "===================================================="

#  ---- YAHAN TAK ----
#  Chahiye: aaj ki date, aur RESULT: PASS
#  FAIL aaye to WAN up nahi hai. STEP 0 ke ping wapas check karo.


# =============================================================
#  STEP 2  --  CERTIFICATES
# =============================================================
#  Master console ka script yahin toot-ta hai. Wo chalata hai:
#      /certificate sign cloudguest-ca ca=cloudguest-ca
#  `ca=` ka matlab hai "isko kaun sign karega" -- koi DOOSRA,
#  pehle se signed CA. Naya banaya cert abhi template hota hai,
#  uske paas CA capability hai hi nahi. Isliye wo command kabhi
#  chal hi nahi sakti thi. Error aata hai:
#      input does not match any value of ca
#
#  Neeche sahi tareeka hai: root CA ko `ca=` ke BINA sign karo.
#  Ye chala lene ke baad generated script ka cert block guard ki
#  wajah se skip ho jaayega aur script aage badh jaayega.
#
#  Signing me 20-40 second lagte hain -- delay isiliye hain.
#
#  >>> Ye cert hotspot ke liye NAHI hai. <<<
#  Ise kabhi `ssl-certificate=` se hsprof1 pe bind mat karna, aur
#  `login-by` me `https` mat daalna. Ye router ka khud ka banaya aur khud
#  ka signed cert hai -- guest ka koi bhi device ise nahi jaanta. Hotspot
#  login page plain HTTP pe hi rehna chahiye, warna login page khulta hi
#  nahi aur login ke baad portal band nahi hota. Poori wajah neeche
#  troubleshooting section me `login-by` ke saath likhi hai.
#  ---- YAHAN SE COPY KARO ----

:put "Purane aadhe-bane certs hata rahe hain..."
/certificate remove [find name~"cloudguest"]
:delay 2s
:put "Root CA bana rahe hain (30-40 sec)..."
/certificate add name=cloudguest-ca common-name=cloudguest-ca key-usage=key-cert-sign,crl-sign,tls-server
/certificate sign cloudguest-ca
:delay 20s
/certificate set [find name="cloudguest-ca"] trusted=yes
:put "Hotspot cert bana rahe hain (30-40 sec)..."
/certificate add name=cloudguest-hotspot-cert common-name=wifi.wyfyguest.com key-usage=tls-server
/certificate sign cloudguest-hotspot-cert ca=cloudguest-ca
:delay 20s
/certificate set [find name="cloudguest-hotspot-cert"] trusted=yes
:put "===================================================="
:if ([:len [/certificate find where name="cloudguest-ca"]] > 0) do={ :put ("  ROOT CA : " . [:tostr [/certificate get [find name="cloudguest-ca"] invalid-after]]) } else={ :put "  ROOT CA : MISSING" }
:if ([:len [/certificate find where name="cloudguest-hotspot-cert"]] > 0) do={ :put ("  LEAF    : " . [:tostr [/certificate get [find name="cloudguest-hotspot-cert"] invalid-after]]) } else={ :put "  LEAF    : MISSING" }
:if ([:len [/certificate find where name~"cloudguest"]] = 2) do={ :put "  RESULT  : 2 cert mile -- upar dono lines pe asli date honi chahiye" } else={ :put "  RESULT  : FAIL -- neeche note padho" }
:put "===================================================="

#  ---- YAHAN TAK ----
#  Chahiye: dono lines pe ek asli expiry date, aur RESULT: PASS
#
#  Agar phir se "input does not match any value of ca" aaye:
#  matlab CA ki signing tab tak poori nahi hui thi. 20 second ruko
#  aur sirf ye teen lines dobara chalao:
#      /certificate add name=cloudguest-hotspot-cert common-name=wifi.wyfyguest.com key-usage=tls-server
#      /certificate sign cloudguest-hotspot-cert ca=cloudguest-ca
#      /certificate set [find name="cloudguest-hotspot-cert"] trusted=yes
#
#  Certs guests ke internet ke liye ZAROORI NAHI hain. Bahut atak
#  jao to STEP 2 chhod ke STEP 3 pe chale jao -- guest flow phir
#  bhi chalega, bas kabhi-kabhi browser warning aayega.


# =============================================================
#  STEP 3  --  MASTER CONSOLE WALA SCRIPT
# =============================================================
#  Ab Master console ka generated script paste karo.
#
#  Master console -> Router kholo -> "Advanced setup script"
#  WireGuard aur RADIUS dono tick karo -> Generate (EK BAAR)
#
#  >> WIZARD MAT USE KARNA <<
#  Panel ke upar ek blue callout hai jo kehta hai ki wizard use
#  karo aur ye page "legacy" hai. Wo ulta hai. Wizard apna script
#  backend se laata hai, isliye jo fixes frontend me lage hain wo
#  usme jaate hi nahi. Wizard ko live tunnel bhi chahiye hota hai,
#  aur na aaye to 13 me se step 2 pe phas jaoge, bina fallback ke.
#
#  >> TURANT .rsc DOWNLOAD KAR LO <<
#  Script ke andar 4 secrets dabe hain (agent credential,
#  WireGuard private key, RADIUS shared secret, API secret) jo
#  SIRF EK BAAR dikhte hain. UI ye batati nahi. Tab band ho gaya
#  to sirf ek recovery hai -- dobara Generate, jo router ko chup-
#  chaap maar deta hai.
#
#  PASTE KARNE KE BAAD ye check karo:
#
#  /ip hotspot walled-garden ip print
#
#  Isme comment="cloudguest-portal-https" wali row honi chahiye.
#  KHAALI HUI TO GUEST PORTAL TAK PAHUNCH HI NAHI PAYEGA -- ye is
#  poore setup ka sabse zaroori ek check hai. Khaali ho to Walled
#  Garden chunk dobara paste karo.
#
#  US ROW MEIN KAUNSA ADDRESS HONA CHAHIYE, YE YAHAN LIKHA HUA NAHI HAI
#  -- JAANBUJH KAR. Device se khud poochho:
#
#  :put [:resolve auth.wyfyguest.com]
#
#  Jo nikle, wahi dst-address row mein hona chahiye. Alag ho to Walled
#  Garden chunk dobara paste karo (wo bhi :resolve hi karta hai).
#
#  Yahan pehle `dst-address=20.219.51.94` likha tha, "expected value" ki
#  tarah. Wo Azure ka address tha. Platform 2026-08-27 ko AWS ap-south-1
#  pe chala gaya aur ab ye naam 13.203.112.174 pe resolve hota hai. Yaani
#  ye runbook ek theek chalte router ko dekh kar operator se kehti ki
#  "galat hai", aur operator use ek mare hue address pe set kar deta --
#  guest portal ko theek karne ke naam par tod deta. Wahi shakal jo
#  `login-by=https,http-pap` wali line ki thi.
#
#  Isliye ab yahan koi IP likhi hi nahi hai. Ek address jo file mein
#  hardcode hai, wo agli migration pe phir se galat ho jayega aur koi
#  ye file dobara khol kar nahi dekhega. `:resolve` kabhi purana nahi
#  hota.
#
#  Agar "WAN CONNECTIVITY CHECK" me ping PASS aaye par DNS FAIL,
#  to wo script ka bug hai, tumhare network ka nahi -- wo check
#  DNS set hone se pehle chalta hai. Ye chalao aur check dobara
#  paste karo:
#
#  /ip dns set servers=8.8.8.8,1.1.1.1 allow-remote-requests=yes


# =============================================================
#  STEP 4  --  JO SCRIPT BHOOL JAATA HAI
# =============================================================
#  Teen cheezein generated script galat chhod deta hai. Teenon
#  chup-chaap galat rehti hain -- koi error nahi aata.
#
#  1. idle-timeout kabhi set nahi hota. Script keepalive-timeout=none
#     karta hai (sahi hai -- phone lock hone pe guests drop ho rahe
#     the), par phir idle-timeout hi akela backstop bachta hai.
#     Wo bhi none hua to sessions KABHI band nahi honge: slots
#     bharte rahenge, RADIUS accounting khuli rahegi, data caps
#     kabhi trigger nahi honge.
#
#  2. Local "guest" hotspot user. RouterOS local users ko RADIUS
#     se PEHLE check karta hai -- matlab wo account poore portal
#     ka bypass hai. Koi OTP nahi, koi session nahi, koi consent
#     record nahi, koi data cap nahi, koi analytics nahi. Aur usko
#     wahi default profile milta hai: 5 devices, unmetered.
#
#  3. Portal redirect files. Script inhe "flash/hotspot/login.html"
#     pe likhta hai, par ye prefix sirf kuch models pe hota hai.
#     Galat model pe paanchon command SAFAL dikhengi aur file
#     badlegi hi nahi -- guest ko Wyfy portal ki jagah MikroTik ka
#     stock blue login page milega.
#  ---- YAHAN SE COPY KARO ----

:if ([:len [/ip hotspot find]] > 0) do={ /ip hotspot set [find] idle-timeout=5m; :put "idle-timeout 5m set kar diya" } else={ :put "!! hotspot hai hi nahi -- STEP 3 poora nahi hua" }
:if ([:len [/ip hotspot user find where name="guest"]] > 0) do={ /ip hotspot user set [find name="guest"] disabled=yes; :put "guest bypass user band kar diya" } else={ :put "guest user hai hi nahi -- theek hai" }
:put "===================================================="
:put "  PORTAL FILES -- asli path yahan dikhega:"
/file print where name~"login.html"
:put "===================================================="
:if ([:len [/file find where name~"login.html"]] = 0) do={ :put "  RESULT : FAIL -- portal files likhi hi nahi gayi" } else={ :put "  RESULT : PASS -- ab neeche contents check karo" }
:put "===================================================="

#  ---- YAHAN TAK ----
#  Upar jo path dikha (flash/hotspot/login.html ya sirf
#  hotspot/login.html) -- usko neeche wali line me daal ke chalao:
#
#  /file print detail where name~"login.html"
#
#  Contents me ye LITERAL text dikhna chahiye:  $(link-login-only)
#  Agar wahan khaali hai ya value aa gayi hai, to redirect page
#  galat likha gaya -- Portal Redirect chunks dobara paste karo.


# =============================================================
#  STEP 5  --  POORA VERIFICATION
# =============================================================
#  Ek saath paste karo. Sab read-only hai, kuch badalta nahi.
#  ---- YAHAN SE COPY KARO ----

:put "========== WYFY ROUTER VERIFY =========="
:put ("  1. Clock            : " . [/system clock get date])
:put ("  2. Internet         : " . [:tostr [/ping 8.8.8.8 count=3]] . " / 3 replies")
:put ("  3. Walled garden IP : " . [:tostr [:len [/ip hotspot walled-garden ip find]]] . "  (chahiye 1 ya zyada)")
:put ("  4. Portal files     : " . [:tostr [:len [/file find where name~"login.html"]]] . "  (chahiye 1)")
:if ([:len [/ip hotspot profile find where name="hsprof1"]] > 0) do={ :put ("  5. Hotspot login-by : " . [:tostr [/ip hotspot profile get [find name="hsprof1"] login-by]]) } else={ :put "  5. Hotspot login-by : MISSING" }
:if ([:len [/ip hotspot find]] > 0) do={ :put ("  6. Idle timeout     : " . [:tostr [/ip hotspot get [find] idle-timeout]]) } else={ :put "  6. Idle timeout     : MISSING" }
:if ([:len [/ip hotspot user profile find where name="default"]] > 0) do={ :put ("  7. Shared users     : " . [:tostr [/ip hotspot user profile get [find name="default"] shared-users]]) } else={ :put "  7. Shared users     : MISSING" }
:put ("  8. WireGuard peers  : " . [:tostr [:len [/interface wireguard peers find]]] . "  (chahiye 1)")
:put ("  9. RADIUS entries   : " . [:tostr [:len [/radius find]]] . "  (chahiye 1)")
:put (" 10. Certificates     : " . [:tostr [:len [/certificate find where name~"cloudguest"]]] . "  (chahiye 2, ya 0 agar skip kiya)")
:put (" 11. Guest bypass     : " . [:tostr [:len [/ip hotspot user find where name="guest" and disabled=no]]] . "  (chahiye 0)")
:put "========================================"
:put "  Tunnel aur RADIUS ki asli haalat:"
/interface wireguard peers print detail
/radius print detail
:put "========================================"

#  ---- YAHAN TAK ----
#
#  KYA DEKHNA HAI
#    1  aaj ki date
#    2  3 / 3 replies
#    3  1 ya zyada  <-- 0 hua to guest portal tak pahunchega hi nahi
#    4  1
#    5  SIRF http-pap. `https` dikhe to wo galti hai, theek karo.
#       (Yahan pehle "https bhi ho to theek hai" likha tha. Wo neeche
#       troubleshooting ke ">>> https KABHI MAT DAALO <<<" se seedha
#       ulta tha, aur operator checklist hi padhta hai. Exception sirf
#       ek hai: agar is router pe wyfy-hotspot-fleet cert BANDHA hua ho
#       to `https,http-pap` sahi hai -- par 2026-09-06 tak fleet mein
#       aisa ek hi router hai, aur uspe bhi cert haath se chadhaya gaya
#       tha. Cert bandha hai ya nahi, ye dekho:
#       /ip hotspot profile print detail where name=hsprof1
#       -- usme ssl-certificate khaali ho aur login-by me https ho, to
#       wahi teen shikayaton wali haalat hai jo neeche likhi hai.)
#    6  00:05:00
#    7  5
#    8  1
#    9  1
#   10  2  (ya 0 agar STEP 2 skip kiya)
#   11  0
#
#  wireguard peers me: last-handshake 2 minute se kam hona chahiye.
#  60 second baad bhi handshake na aaye = tunnel down hai. Iske
#  aage sab kuch fail hoga, aur zyadatar chup-chaap. Ruk jao.
#
#  radius me: entry disabled na ho, timeout=3s ho.


# =============================================================
#  STEP 6  --  PHONE TEST  (ekmatra test jo maayne rakhta hai)
# =============================================================
#  Dashboard sab green dikha sakta hai aur guest ko phir bhi kuch
#  na mile. Ye ho chuka hai. Isliye ye step optional nahi hai.
#
#  Phone pe network pehle FORGET karo, aur MOBILE DATA BAND karo
#  -- warna phone chupke se LTE use karega aur har result jhoota
#  hoga.
#
#  1. Guest SSID join karo
#     -> ~5 second me sign-in sheet khud khulni chahiye
#
#  2. KUCH BHI KARNE SE PEHLE ADDRESS BAR DEKHO
#     -> "link-login-only=" ke aage asli value honi chahiye
#     -> khaali ya gayab = redirect page galat likha gaya
#     -> 3 second ka check hai aur sabse zyada kaam ka
#
#  3. Portal load ho -> venue ka logo -> sign-in card, 3 sec ke andar
#
#  4. Asli number daalo, OTP aaye, submit karo
#
#  5. Koi aisi site kholo jo pehle kabhi na kholi ho
#     (cache se load hui to test jhootha hai)
#
#  6. WiFi OFF karke ON karo
#     -> bina OTP dobara daale internet wapas aa jaana chahiye
#     -> purane outage ke 7 me se 3 root causes SIRF reconnect pe
#        dikhte the. Ye step kiye bina wo teenon pass ho jayenge.
#
#  Phir router pe:
#
#  /ip hotspot active print
#  /radius monitor 0 once
#
#  Chahiye: phone active list me ho, accepts badh raha ho, aur
#  bad-replies ZERO ho. bad-replies rejects aur timeouts se alag
#  chautha counter hai -- reply aaya to sahi par validate nahi hua.
#
#  >> AGAR LOGIN KE TURANT BAAD "Your session has expired" AAYE
#     PAR INTERNET CHAL RAHA HO <<
#  Wo expiry NAHI hai. Phone ka captive sheet storage block kar
#  raha hai; guest sach me online hai. "Sign in again" mat dabana
#  -- sheet band karke normal browser kholo. Ye dikhe to batao,
#  ek pending fix must-ship ho jaata hai.


# =============================================================
#  KUCH GALAT HO TO
# =============================================================
#  Portal khulta hi nahi / "no internet"
#      /ip hotspot walled-garden ip print
#      khaali -> Walled Garden chunk dobara paste karo
#
#  MikroTik ka blue login page dikh raha hai
#      /file print where name~"login.html"
#      path galat -> paanchon /file set asli path se dobara
#
#  Portal se pehle certificate warning
#      wahi wajah -- walled-garden IP entry missing hai
#
#  OTP verify hua, phir spinner atka
#      /radius monitor 0 once
#      timeouts badh rahe -> tunnel down
#      rejects          -> secret galat
#      bad-replies      -> hub-side Message-Authenticator
#
#  Guest credentials daalta hai, kuch hota hi nahi
#      /ip hotspot profile print detail where name=hsprof1
#      login-by me http-pap nahi -> set [find name=hsprof1] login-by=http-pap
#
#      >>> `https` KABHI MAT DAALO. Sirf `http-pap`. <<<
#      Is line mein pehle `login-by=https,http-pap` likha tha. Wo galat tha
#      aur teen alag shikayaton ki jad tha -- 2026-08-23 ko ek provisioned
#      hEX pe Windows aur macOS dono pe LAN cable se confirm hua:
#
#        1. Login page bilkul nahi khulta (Windows/macOS)
#        2. Login ke baad captive portal ki window band nahi hoti
#        3. Android pe certificate warning
#
#      Wajah: `https` hote hi RouterOS unauthenticated guest ko
#      http://<dns-name>/login ki jagah https://<dns-name>/login pe bhejta
#      hai -- us cert ke saath jo is script ne KHUD banaya aur khud sign
#      kiya hai (STEP 2 dekho), aur jise duniya ka koi device nahi jaanta.
#      Har OS "main online hoon?" ka faisla ek plain-HTTP URL fetch karke
#      leta hai. TLS handshake fail hona HTTP-level jawab hai hi nahi, to
#      probe transport mein hi mar jaati hai aur OS seedha "no internet"
#      dikha deta hai -- ek globe icon, aur click karne ko kuch nahi.
#
#      Dono generators (backend renderer aur Master Console) ab sirf
#      `login-by=http-pap` likhte hain. Ye doc unse peeche reh gaya tha.
#
#  "no more sessions are allowed for user"
#      /ip hotspot user profile set [find name=default] shared-users=5
#
#  Router chal raha hai par dashboard pe offline
#      /system clock print
#      date galat -> STEP 1, phir Heartbeat chunk dobara paste karo
#
#  WireGuard kabhi connect nahi hota
#      /ip firewall filter print
#      cloudguest-fw-allow-wg-mgmt row cloudguest-fw-drop-wan-input
#      ke UPAR honi chahiye -> move se theek karo
#
#  "input does not match any value of ca"
#      /certificate remove [find name~"cloudguest"]
#      phir STEP 2 dobara. Ya poora skip kar do.
# =============================================================
