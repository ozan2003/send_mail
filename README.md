# Send mail

- Send mail with school mail.
- Reads mail subject and body from a .toml file.
- Adds the CV as an attachment.
- Sends the mail to the specified recipient(s).

## Configuration

If you want to use this script as is, you will need to configure the following:

- Mail address and password as environment variables. (default names: `SAU_MAIL` and `SAU_APP_PASSWD`)
- The mail subject and body in a .toml file. (default path: `~/.config/send_cv.toml`)
- The CV file path. (default path: `~/Documents/CV/TR/OzanMalciBilMuhCV.pdf`)

Refer to `-h/--help` for usage.
