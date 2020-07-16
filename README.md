# check_hpe_msl_quickstatus
Check HPE MSL QuickStatus

Checks the HPE MSL QuickStatus for both health errors currently present and in the log that are not cleared.

Verified against HPE MSL 3040.

## How it works
Uses selenium to browse the webpages of the HPE MSL as a user. It then retrieves the completed responses of the data it wants and parses those for the relevant data.

## Requirements
python3-selenium
(Headless) Chrome / Chromium 

### Debian
```
apt-get install python3-selenium chromium chromium-driver python3-requests
```

## Icinga2 Check Command definition
```
object CheckCommand "hpe_msl_health" {
    import "plugin-check-command"
    command = [ PluginDir + "/check_hpe_msl_quickstatus.py" ]
    timeout = 30s
    arguments += {
        "--host" = "$host.address$"
        "--ignoreCertificateErrors" = {
            set_if = "$msl_ignoreCertificateErrors$"
        }
        "--password" = "$msl_password$"
        "--username" = "$msl_username$"
    }
    vars.msl_ignoreCertificateErrors = false
    vars.msl_username = "user"
}
```
