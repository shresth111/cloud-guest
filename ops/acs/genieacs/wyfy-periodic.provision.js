// GenieACS provision "wyfy-periodic" (API_CONTRACT §6.5).
//
// 1. Keeps periodic inform ON. Nothing else is ever written. The backend's
//    task model depends on it: connection requests rarely reach a CPE behind
//    NAT, so every refresh/reboot runs at the device's next periodic inform.
// 2. READS ManagementServer.Username and PeriodicInformInterval into the
//    device document, at most hourly. The Inform does not carry Username, and
//    GenieACS only stores what something asked for. Without this read, the
//    backend's sync query (API_CONTRACT §6.2, match on
//    *.ManagementServer.Username._value) would match no device at all.
//    Username is not a secret; no password parameter is ever declared here.
//
// It never sets the interval: the MikroTik script owns that.

const hourAgo = Date.now() - 3600 * 1000;
const tr181 = declare("Device.ManagementServer.PeriodicInformEnable", { path: 1 });
const root = tr181.size ? "Device" : "InternetGatewayDevice";

declare(root + ".ManagementServer.PeriodicInformEnable", { value: 1 }, { value: true });
declare(root + ".ManagementServer.Username", { value: hourAgo });
declare(root + ".ManagementServer.PeriodicInformInterval", { value: hourAgo });
